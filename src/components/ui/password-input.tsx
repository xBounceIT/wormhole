import * as React from 'react';
import { Eye, EyeOff } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { useDialogOpen } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

function PasswordInput({
  className,
  id,
  disabled,
  visible: controlledVisible,
  onVisibilityChange,
  toggleDisabled = false,
  ...props
}: Omit<React.ComponentProps<typeof Input>, 'type'> & {
  visible?: boolean;
  onVisibilityChange?: (visible: boolean) => void;
  toggleDisabled?: boolean;
}) {
  const generatedId = React.useId();
  const inputId = id ?? generatedId;
  const open = useDialogOpen();
  const [uncontrolledVisible, setVisible] = React.useState(false);
  const visible = open !== false && !disabled && (controlledVisible ?? uncontrolledVisible);
  const label = visible ? 'Hide password' : 'Show password';

  React.useLayoutEffect(() => {
    if (open === false || disabled) setVisible(false);
  }, [open, disabled]);

  return (
    <div className="relative w-full min-w-0">
      <Input
        {...props}
        className={cn(className, 'pr-9')}
        disabled={disabled}
        id={inputId}
        spellCheck={false}
        type={visible ? 'text' : 'password'}
      />
      <Button
        aria-controls={inputId}
        aria-label={label}
        aria-pressed={visible}
        className="absolute inset-y-0 right-0.5 my-auto text-muted-foreground transition-colors active:not-aria-[haspopup]:translate-y-0"
        disabled={disabled || toggleDisabled}
        onClick={() => {
          setVisible(!visible);
          onVisibilityChange?.(!visible);
        }}
        size="icon-sm"
        title={label}
        type="button"
        variant="ghost"
      >
        {visible ? <EyeOff /> : <Eye />}
      </Button>
    </div>
  );
}

export { PasswordInput };
