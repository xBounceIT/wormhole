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
  onSort?: (column: SftpSortColumn) => void;
  className?: string;
  children?: ReactNode;
}) {
  const label = column === 'name' ? 'Name' : column === 'size' ? 'Size' : 'Modified';
  const active = !!onSort && sortColumn === column;
  const controlClassName = `flex h-6 items-center gap-1 font-mono text-[9px] font-medium uppercase leading-4 tracking-[0.12em] text-muted-foreground ${column === 'name' ? 'shrink-0 text-left' : column === 'size' ? 'w-full justify-end text-right' : 'w-full text-left'}`;
  const content = (
    <>
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
    </>
  );
  return (
    <div
      role="columnheader"
      aria-colindex={columnIndex}
      aria-sort={onSort ? (active ? (ascending ? 'ascending' : 'descending') : 'none') : undefined}
      className={`flex min-w-0 items-center gap-2 font-mono text-[9px] font-medium leading-4 tracking-[0.12em] ${className}`}
    >
      {onSort ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              className={`${controlClassName} hover:text-foreground`}
              onClick={() => onSort(column)}
              type="button"
            >
              {content}
            </button>
          </TooltipTrigger>
          <TooltipContent side="top">Sort by {label.toLowerCase()}</TooltipContent>
        </Tooltip>
      ) : (
        <span className={controlClassName}>{content}</span>
      )}
      {children}
    </div>
  );
}
