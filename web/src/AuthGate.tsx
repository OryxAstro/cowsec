import { useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import App from './App';
import Login from './Login';
import SettingsModal from './SettingsModal';
import { UNAUTHORIZED_EVENT, postJSON, type Identity, type MeResponse } from './session';

// Shows the login page until /api/auth/me confirms a session, then the app.
// Any 401 from the API (expired/revoked session) returns to the login page.
export default function AuthGate() {
  const [identity, setIdentity] = useState<Identity | null | undefined>(undefined);
  const [notice, setNotice] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const signedIn = useRef(false);
  useEffect(() => {
    signedIn.current = !!identity;
  }, [identity]);

  useEffect(() => {
    fetch('/api/auth/me', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((me: MeResponse | null) => setIdentity(me ? me.identity : null))
      .catch(() => setIdentity(null));

    const expired = () => {
      if (signedIn.current) setNotice('Your session expired. Please sign in again.');
      setIdentity(null);
      setShowSettings(false);
    };
    window.addEventListener(UNAUTHORIZED_EVENT, expired);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, expired);
  }, []);

  const logout = async () => {
    await postJSON('/api/auth/logout', {});
    setShowSettings(false);
    setNotice('');
    setIdentity(null);
  };

  if (identity === undefined) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
        <Loader2 className="w-6 h-6 animate-spin text-slate-500" />
      </div>
    );
  }

  if (!identity) {
    return (
      <Login
        notice={notice}
        onSignedIn={(id) => {
          setNotice('');
          setIdentity(id);
        }}
      />
    );
  }

  return (
    <>
      <App
        session={identity}
        onLogout={logout}
        onOpenSettings={() => setShowSettings(true)}
      />
      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} onLogout={logout} />}
    </>
  );
}
