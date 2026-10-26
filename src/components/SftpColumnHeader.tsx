import { type ReactNode } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { type SftpSortColumn } from '../sftp-state';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';

export function SftpColumnHeader({
  column,
  columnIndex,
  sortColumn,
  ascending,
  onSort,
  className = '',
  children,
}: {
  column: SftpSortColumn;
  columnIndex: number;
  sortColumn: SftpSortColumn;
  ascending: boolean;
  onSort: (column: SftpSortColumn) => void;
  className?: string;
  children?: ReactNode;
}) {
  const label = column === 'name' ? 'Name' : column === 'size' ? 'Size' : 'Modified';
  const active = sortColumn === column;
  return (
    <div
      role="columnheader"
      aria-colindex={columnIndex}
      aria-sort={active ? (ascending ? 'ascending' : 'descending') : 'none'}
      className={`flex min-w-0 items-center gap-2 font-mono text-[9px] font-medium leading-4 tracking-[0.12em] ${className}`}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            className={`flex h-6 items-center gap-1 font-mono text-[9px] font-medium uppercase leading-4 tracking-[0.12em] text-muted-foreground hover:text-foreground ${column === 'name' ? 'shrink-0 text-left' : column === 'size' ? 'w-full justify-end text-right' : 'w-full text-left'}`}
            onClick={() => onSort(column)}
            type="button"
          >
            <span>{label}</span>
            <span aria-hidden="true" className="grid size-3 shrink-0 place-items-center">
              {active ? (
                ascending ? (
                  <ChevronUp className="size-3" />
                ) : (
                  <ChevronDown className="size-3" />
                )
              ) : null}
            </span>
          </button>
        </TooltipTrigger>
        <TooltipContent side="top">Sort by {label.toLowerCase()}</TooltipContent>
      </Tooltip>
      {children}
    </div>
  );
}
