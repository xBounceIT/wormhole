import { Search } from 'lucide-react';
import { type KeyboardEventHandler, type Ref } from 'react';
import { Input } from './ui/input';

export function SftpSearchInput({
  label,
  value,
  onChange,
  id,
  inputRef,
  onKeyDown,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  id: string;
  inputRef: Ref<HTMLInputElement>;
  onKeyDown: KeyboardEventHandler<HTMLInputElement>;
}) {
  return (
    <div className="relative min-w-0 flex-1 font-sans text-[11px] font-normal normal-case tracking-normal">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-muted-foreground" />
      <Input
        id={id}
        ref={inputRef}
        type="search"
        aria-label={label}
        className="h-6 min-w-0 pl-7 pr-3 font-sans text-[11px] font-normal normal-case tracking-normal md:text-[11px]"
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={onKeyDown}
        placeholder="Search…"
        value={value}
      />
    </div>
  );
}
