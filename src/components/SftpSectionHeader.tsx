import { useId, useLayoutEffect, useRef, useState } from 'react';
import { Search, X } from 'lucide-react';
import { type SftpSortColumn } from '../sftp-state';
import { SftpColumnHeader } from './SftpColumnHeader';
import { SftpSearchInput } from './SftpSearchInput';
import { Button } from './ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';

export function SftpSectionHeader({
  pane,
  kind,
  sortColumn,
  ascending,
  onSort,
  search,
  onSearchChange,
}: {
  pane: 'local' | 'remote';
  kind: 'tree' | 'files';
  sortColumn: SftpSortColumn;
  ascending: boolean;
  onSort: (column: SftpSortColumn) => void;
  search: string;
  onSearchChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const expanded = open || search.length > 0;
  const inputId = useId();
  const input = useRef<HTMLInputElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const focusTarget = useRef<'input' | 'trigger' | undefined>(undefined);
  const section = kind === 'tree' ? 'directory tree' : 'folder';
  const label = `Search ${pane} ${section}`;
  const buttonLabel = expanded ? `Close ${pane} ${section} search` : label;
  useLayoutEffect(() => {
    if (focusTarget.current === 'input') input.current?.focus({ preventScroll: true });
    else if (focusTarget.current === 'trigger') trigger.current?.focus({ preventScroll: true });
    focusTarget.current = undefined;
  }, [expanded]);

  function closeSearch() {
    focusTarget.current = 'trigger';
    setOpen(false);
    onSearchChange('');
  }

  const toggle = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          ref={trigger}
          aria-label={buttonLabel}
          aria-expanded={expanded}
          aria-controls={inputId}
          className="absolute inset-y-0 right-2 my-auto size-6 p-0 text-muted-foreground transition-colors active:not-aria-[haspopup]:translate-y-0"
          size="icon-xs"
          variant="ghost"
          type="button"
          onClick={() => {
            if (expanded) closeSearch();
            else {
              focusTarget.current = 'input';
              setOpen(true);
            }
          }}
        >
          {expanded ? <X className="size-3.5" /> : <Search className="size-3.5" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{buttonLabel}</TooltipContent>
    </Tooltip>
  );

  return (
    <div
      role="row"
      aria-rowindex={1}
      data-sftp-tree-header={kind === 'tree' ? true : undefined}
      data-sftp-file-header={kind === 'files' ? true : undefined}
      className="sticky top-0 z-10 bg-background"
    >
      <div className="relative h-10 border-b border-border bg-muted/20">
        {expanded ? (
          <div
            role="columnheader"
            aria-colindex={1}
            aria-colspan={kind === 'tree' ? 3 : 5}
            className="flex h-full min-w-0 items-center pl-3 pr-11"
          >
            <SftpSearchInput
              id={inputId}
              inputRef={input}
              label={label}
              value={search}
              onChange={onSearchChange}
              onKeyDown={(event) => {
                if (event.key === 'Escape') {
                  event.preventDefault();
                  event.stopPropagation();
                  closeSearch();
                }
              }}
            />
            {toggle}
          </div>
        ) : (
          <div
            className={`grid h-full items-center gap-x-2.5 px-[22px] py-1 ${kind === 'tree' ? 'grid-cols-[minmax(0,1fr)_5.25rem_7.75rem]' : 'grid-cols-[1rem_1.5rem_minmax(0,1fr)_5.25rem_7.75rem]'}`}
          >
            {kind === 'files' ? (
              <>
                <span role="columnheader" aria-colindex={1}>
                  <span className="sr-only">Selection</span>
                </span>
                <span role="columnheader" aria-colindex={2} aria-hidden="true" />
              </>
            ) : null}
            {(['name', 'size', 'modified'] as const).map((column, index) => (
              <SftpColumnHeader
                key={column}
                column={column}
                columnIndex={index + (kind === 'tree' ? 1 : 3)}
                sortColumn={sortColumn}
                ascending={ascending}
                onSort={onSort}
                className={
                  kind === 'tree' && column === 'name'
                    ? 'pl-[60px]'
                    : column === 'modified'
                      ? 'pr-3'
                      : undefined
                }
              >
                {column === 'modified' ? toggle : null}
              </SftpColumnHeader>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
