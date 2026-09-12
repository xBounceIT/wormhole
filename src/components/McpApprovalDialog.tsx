import { useLayoutEffect, useRef } from 'react';
import { AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

export function McpApprovalDialog({
  approval,
  onDecision,
}: {
  approval: WormholeMcpApproval | undefined;
  onDecision: (approved: boolean) => void;
}) {
  const contentRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (contentRef.current) contentRef.current.scrollTop = 0;
  }, [approval?.requestId]);
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open) onDecision(false);
      }}
      open={approval !== undefined}
    >
      <DialogContent
        ref={contentRef}
        className="z-[60] max-h-[calc(100dvh-2rem)] overflow-y-auto border-border/70 bg-card text-card-foreground sm:max-w-2xl"
        overlayClassName="z-[60]"
      >
        <DialogHeader>
          <DialogTitle>
            {approval?.approvalKind === 'open_connection'
              ? 'Allow AI agent to open this connection?'
              : 'Allow AI agent control?'}
          </DialogTitle>
          <DialogDescription>
            {approval?.approvalKind === 'open_connection'
              ? 'An MCP client is asking Wormhole to open a saved connection.'
              : "An MCP client is requesting access to one of Wormhole's live SSH sessions."}
          </DialogDescription>
        </DialogHeader>
        {approval ? (
          <div className="space-y-3 rounded-lg border border-border/70 bg-muted/20 p-3 text-xs">
            <div className="flex items-start gap-2">
              <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-400" />
              <div className="min-w-0 space-y-1">
                <p className="font-medium">
                  {approval.approvalKind === 'open_connection' && approval.connectionFolder
                    ? `${approval.connectionFolder} / ${approval.title}`
                    : approval.title || 'SSH session'}
                </p>
                <p className="break-all text-muted-foreground">
                  {approval.approvalKind === 'open_connection'
                    ? `${approval.protocol?.toUpperCase()} · ${approval.host}${
                        approval.port > 0 ? `:${approval.port}` : ''
                      }${approval.path ?? ''}`
                    : `${approval.username}@${approval.host}:${approval.port}`}
                </p>
                <p className="text-muted-foreground">
                  Requested tool: <span className="font-mono">{approval.tool}</span>
                </p>
              </div>
            </div>
            <div className="min-w-0 space-y-2">
              <p className="font-medium">Requested execution</p>
              {approval.executionPreview ? (
                <>
                  <pre
                    key={approval.requestId}
                    aria-label="Requested execution"
                    className="max-h-64 select-text overflow-auto whitespace-pre-wrap break-all rounded-md border border-border/70 bg-background/70 p-3 font-mono text-xs leading-relaxed"
                    dir="ltr"
                    tabIndex={0}
                  >
                    {approval.executionPreview.content}
                  </pre>
                  {approval.executionPreview.redacted ? (
                    <p className="text-muted-foreground">Detected sensitive values are hidden.</p>
                  ) : null}
                  {approval.executionPreview.truncated ? (
                    <p className="text-amber-500 dark:text-amber-400">
                      Preview truncated. Only the beginning of the request is shown.
                    </p>
                  ) : null}
                </>
              ) : (
                <p className="text-muted-foreground">Execution details are unavailable.</p>
              )}
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              {approval.approvalKind === 'open_connection'
                ? 'This approval applies only to this open request. Every MCP request to open a connection requires a new approval.'
                : 'Allowing this request grants the MCP client access until you disconnect the AI agent or close this session. MCP tools can run only while Wormhole is unlocked.'}
            </p>
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={() => onDecision(false)} type="button" variant="ghost">
            Deny
          </Button>
          <Button onClick={() => onDecision(true)} type="button">
            Allow
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
