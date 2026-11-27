export function clearSecretInput(input: HTMLInputElement | null): void {
  if (input) input.value = '';
}

export function takeOneShotSecret(input: HTMLInputElement | null): string {
  if (!input) return '';
  const secret = input.value;
  clearSecretInput(input);
  return secret;
}
