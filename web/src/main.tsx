import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/plus-jakarta-sans/400.css';
import '@fontsource/plus-jakarta-sans/500.css';
import '@fontsource/plus-jakarta-sans/600.css';
import '@fontsource/plus-jakarta-sans/700.css';
import '@fontsource/plus-jakarta-sans/800.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/600.css';
import './index.css';
import AuthGate from './AuthGate';
import SetupWizard from './SetupWizard';
import CowSecLogo from './CowSecLogo';
import { installFetchInterceptor } from './session';

installFetchInterceptor();

interface SetupState { setupMode: boolean; wizardOnThisListener?: boolean }

// The same UI is served by the console and, before setup is finished, by the one-time
// setup listener. Ask the server which one this is.
function Root() {
  const [state, setState] = useState<SetupState | null>(null);
  useEffect(() => {
    fetch('/api/setup/state', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : { setupMode: false }))
      .then(setState)
      .catch(() => setState({ setupMode: false }));
  }, []);
  if (!state) return <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-app)' }} />;
  if (state.wizardOnThisListener) return <SetupWizard />;
  if (state.setupMode) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4" style={{ backgroundColor: 'var(--bg-app)' }}>
        <div className="max-w-md text-center space-y-4">
          <CowSecLogo className="w-20 h-20 mx-auto" />
          <h1 className="text-2xl font-extrabold text-white">The barn isn't built yet</h1>
          <p className="text-sm text-slate-400">
            Finish setting up CowSec first. On the server, run <code className="font-mono text-amber-200">sudo cowsec-setup</code> to get the setup address and token.
          </p>
        </div>
      </div>
    );
  }
  return <AuthGate />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
