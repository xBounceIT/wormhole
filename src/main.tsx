import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';
import { applyTheme, getInitialTheme } from './theme';

// Resolve the stored/system theme before React renders so the very first painted
// frame already has the correct background. Deferring this to a post-mount effect
// leaves a light-theme frame visible until the `.dark` class lands — the startup
// flash.
applyTheme(getInitialTheme());

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
