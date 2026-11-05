import { ipcRenderer } from 'electron';

window.addEventListener('DOMContentLoaded', () => {
  const input = document.querySelector<HTMLInputElement>('#secret')!;
  const cancel = () => {
    input.value = '';
    ipcRenderer.send('fortinet-ipsec:secret-response', { cancelled: true });
  };
  document.querySelector('form')!.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = input.value;
    input.value = '';
    ipcRenderer.send('fortinet-ipsec:secret-response', { value });
  });
  document.querySelector('#cancel')!.addEventListener('click', cancel);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') cancel();
  });
});
