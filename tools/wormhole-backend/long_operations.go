package main

import (
	"context"
	"errors"
	"fmt"
)

type operationProgress func(phase, detail string, percent int)

func reportOperationProgress(progress operationProgress, phase, detail string, percent int) {
	if progress != nil {
		progress(phase, detail, percent)
	}
}

func progressBetween(start, end, completed, total int) int {
	if total <= 0 {
		return end
	}
	if completed < 0 {
		completed = 0
	} else if completed > total {
		completed = total
	}
	return start + ((end-start)*completed)/total
}

func (m *vncManager) startBackendOperation(command backendCommand) {
	ctx, cancel := context.WithCancel(context.Background())
	pending := &pendingBackendOperation{cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	if _, exists := m.operations[command.SessionID]; exists {
		m.mu.Unlock()
		cancel()
		m.respond(command.ID, errors.New("an operation with this id is already running"))
		return
	}
	m.operations[command.SessionID] = pending
	m.mu.Unlock()

	progress := func(phase, detail string, percent int) {
		if ctx.Err() != nil {
			return
		}
		if percent < 0 {
			percent = 0
		} else if percent > 100 {
			percent = 100
		}
		m.emit(backendEvent{
			Type:      "operation.progress",
			SessionID: command.SessionID,
			Phase:     phase,
			Detail:    detail,
			Percent:   percent,
		})
	}

	go func() {
		defer cancel()
		result, err := m.runBackendOperation(ctx, command, progress)
		m.mu.Lock()
		if current := m.operations[command.SessionID]; current == pending {
			delete(m.operations, command.SessionID)
		}
		close(pending.done)
		m.mu.Unlock()
		if errors.Is(err, context.Canceled) {
			err = errors.New("Operation cancelled.")
		}
		m.respondResult(command.ID, result, err)
	}()
}

func (m *vncManager) runBackendOperation(
	ctx context.Context,
	command backendCommand,
	progress operationProgress,
) (any, error) {
	switch command.Action {
	case "backup.export":
		return exportBackupContext(ctx, m.databasePath, backupRequest{
			Path: command.Path, Password: command.Password,
		}, progress)
	case "backup.import":
		return importBackupContext(ctx, m.databasePath, backupRequest{
			Path: command.Path, Password: command.Password,
		}, progress)
	case "mremote.import.commit":
		return commitMRemoteImportContextWithProgress(ctx, m.databasePath, mremoteImportRequest{
			Path:          command.Path,
			Password:      command.Password,
			StructureOnly: command.StructureOnly,
			PlanNonce:     command.PlanNonce,
			PlanToken:     command.PlanToken,
		}, progress)
	default:
		return nil, fmt.Errorf("unsupported operation %q", command.Action)
	}
}

func (m *vncManager) cancelBackendOperation(command backendCommand) {
	m.mu.Lock()
	pending := m.operations[command.SessionID]
	if pending != nil {
		pending.cancel()
	}
	m.mu.Unlock()
	if pending != nil {
		<-pending.done
	}
	m.respond(command.ID, nil)
}
