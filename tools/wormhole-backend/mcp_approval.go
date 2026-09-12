package main

import (
	"context"
	"errors"
)

type mcpApprovalMode string

const (
	mcpApprovalFullAccess    mcpApprovalMode = "full-access"
	mcpApprovalAlwaysAsk     mcpApprovalMode = "always-ask"
	mcpApprovalOnFirstAccess mcpApprovalMode = "first-access"
	mcpApprovalModeKey                       = "McpApprovalMode"
)

func validMcpApprovalMode(mode mcpApprovalMode) bool {
	return mode == mcpApprovalFullAccess || mode == mcpApprovalAlwaysAsk || mode == mcpApprovalOnFirstAccess
}

func (controller *mcpController) setApprovalMode(mode mcpApprovalMode) (mcpStatusResponse, error) {
	if !validMcpApprovalMode(mode) {
		return mcpStatusResponse{}, errors.New("MCP approval mode is invalid")
	}
	controller.approvalMu.Lock()
	err := writeSettingsValues(controller.server.databasePath, map[string]any{mcpApprovalModeKey: mode})
	if err == nil {
		controller.applyApprovalModeLocked(mode)
	}
	controller.approvalMu.Unlock()
	if err != nil {
		return mcpStatusResponse{}, err
	}
	return controller.status()
}

// A policy change revokes remembered decisions and pending requests atomically. An approval
// accepted just before the change must also pass the generation check before it can proceed.
func (controller *mcpController) applyApprovalModeLocked(mode mcpApprovalMode) {
	if controller.approvalMode == mode {
		return
	}
	controller.approvalMode = mode
	controller.approvalGeneration++
	for sessionID, approved := range controller.decisions {
		if approved {
			controller.trackedSessions[sessionID] = true
		}
	}
	clear(controller.decisions)
	for requestID, waiter := range controller.pending {
		delete(controller.pending, requestID)
		waiter.err = errors.New("MCP approval mode changed. Retry the request.")
		controller.emitApprovalCancelled(waiter)
		close(waiter.done)
	}
	clear(controller.pendingByTarget)
	controller.emitSessionAccessChangesLocked()
}

func (controller *mcpController) checkApprovalGeneration(waiter *mcpApprovalWaiter) error {
	controller.approvalMu.Lock()
	defer controller.approvalMu.Unlock()
	if controller.locked {
		return errors.New("Wormhole is locked. Unlock the app before using MCP tools.")
	}
	if waiter.generation != controller.approvalGeneration {
		return errors.New("MCP approval mode changed. Retry the request.")
	}
	return nil
}

func (controller *mcpController) sessionConnected(native *sshNativeSession) {
	controller.approvalMu.Lock()
	defer controller.approvalMu.Unlock()
	if native.isClosed() {
		return
	}
	controller.trackedSessions[native.id] = true
	if controller.approvalMode == mcpApprovalFullAccess {
		controller.emitSessionAccessLocked(native.id)
	}
}

// A nil session denotes an inventory tool. Only always-ask prompts for inventory, and only
// first-access shares an approval (and its decision) between requests for the same session.
func (controller *mcpController) ensureApproval(ctx context.Context, native *sshNativeSession, tool string, arguments mcpExecutionArguments) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.approvalMu.Lock()
	if controller.locked {
		controller.approvalMu.Unlock()
		return errors.New("Wormhole is locked. Unlock the app before using MCP tools.")
	}
	if native != nil && native.isClosed() {
		controller.approvalMu.Unlock()
		return errSSHSessionClosed
	}
	mode := controller.approvalMode
	if mode == mcpApprovalFullAccess || native == nil && mode == mcpApprovalOnFirstAccess {
		controller.approvalMu.Unlock()
		return nil
	}
	event := sshWireEvent{
		Type: "mcp.approval", Tool: tool, ApprovalKind: "tool", ApprovalMode: mode,
		SessionID: "mcp-inventory", Title: "Wormhole workspace",
	}
	var sessionDone <-chan struct{}
	remember := native != nil && mode == mcpApprovalOnFirstAccess
	if native != nil {
		event.SessionID = native.id
		event.ApprovalKind = "session_control"
		event.Host, event.Port = native.mcpSession.Host, native.mcpSession.Port
		event.Username, event.Title = native.mcpSession.Username, native.mcpSession.Title
		sessionDone = native.done
	}
	if remember {
		if approved, exists := controller.decisions[event.SessionID]; exists {
			controller.approvalMu.Unlock()
			if !approved {
				return errors.New("the user denied AI-agent control of that session")
			}
			return nil
		}
		if pending := controller.pendingByTarget[event.SessionID]; pending != nil {
			pending.waiters++
			controller.approvalMu.Unlock()
			return controller.waitForApproval(ctx, pending, sessionDone)
		}
	}
	if len(controller.pending) >= mcpMaxPendingApprovals {
		controller.approvalMu.Unlock()
		return errors.New("too many MCP approval requests are pending")
	}
	requestID, err := newMcpRequestID()
	if err != nil {
		controller.approvalMu.Unlock()
		return err
	}
	waiter := &mcpApprovalWaiter{
		requestID: requestID, sessionID: event.SessionID, done: make(chan struct{}),
		waiters: 1, rememberDecision: remember, generation: controller.approvalGeneration,
	}
	controller.pending[requestID] = waiter
	if remember {
		controller.pendingByTarget[event.SessionID] = waiter
	}
	event.RequestID = requestID
	event.ExecutionPreview = newMcpExecutionPreview(arguments)
	controller.server.output.write(event)
	controller.approvalMu.Unlock()
	return controller.waitForApproval(ctx, waiter, sessionDone)
}

func (controller *mcpController) waitForApproval(ctx context.Context, waiter *mcpApprovalWaiter, sessionDone <-chan struct{}) error {
	select {
	case <-waiter.done:
		controller.approvalMu.Lock()
		approved, waitErr := waiter.approved, waiter.err
		controller.approvalMu.Unlock()
		if waitErr != nil {
			return waitErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !approved {
			return errors.New("the user denied the MCP request")
		}
		select {
		case <-sessionDone:
			return errSSHSessionClosed
		default:
		}
		return controller.checkApprovalGeneration(waiter)
	case <-ctx.Done():
		controller.releasePending(waiter)
		return ctx.Err()
	case <-sessionDone:
		controller.releasePending(waiter)
		return errSSHSessionClosed
	}
}
