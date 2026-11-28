// Runs alongside the operation-specific sandbox preload. This document needs
// only the parent's appearance, with no additional renderer API.
window.addEventListener(
  'DOMContentLoaded',
  () => {
    const argument = process.argv.find((item) => item.startsWith('--wormhole-appearance='));
    const oled = argument === '--wormhole-appearance=oled';
    const dark =
      oled ||
      argument === '--wormhole-appearance=dark' ||
      (argument === '--wormhole-appearance=system' &&
        matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.classList.toggle('oled', oled);
  },
  { once: true },
);
