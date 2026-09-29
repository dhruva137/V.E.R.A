import { AuthProvider, useAuth } from './lib/auth';
import { PrefsProvider } from './lib/prefs';
import { ScanProvider } from './lib/scan';
import { ToastProvider, Callout, Button } from './components/ui';
import Shell from './components/Shell';
import SignIn from './pages/SignIn';
import Landing from './landing/Landing';
import { useState } from 'react';

const ENTERED = 'vera.entered';
const entered = () => { try { return sessionStorage.getItem(ENTERED) === '1' || location.hash.includes('skip-landing'); } catch { return true; } };

function Gate() {
  const auth = useAuth();
  const [inside, setInside] = useState(entered);
  if (!inside) {
    return <Landing onEnter={() => { try { sessionStorage.setItem(ENTERED, '1'); } catch { /* private window: show again next time */ } window.scrollTo(0, 0); setInside(true); }} />;
  }
  if (auth.loading) return <div className="page" aria-busy="true" />;
  if (auth.error && !auth.user) {
    return (
      <div className="page" style={{ maxWidth: '40rem', paddingTop: '20vh' }}>
        <Callout tone="bad" title="The V.E.R.A. engine is not answering."
          action={<Button onClick={auth.refresh}>Try again</Button>}>
          <p>Start it with <code>cd backend &amp;&amp; python main.py</code>, then try again. The dashboard talks only to
            the engine on this machine.</p>
        </Callout>
      </div>
    );
  }
  if (auth.auth && !auth.user) return <SignIn />;
  return (
    <ScanProvider>
      <Shell />
    </ScanProvider>
  );
}

export default function App() {
  return (
    <PrefsProvider>
      <ToastProvider>
        <AuthProvider>
          <Gate />
        </AuthProvider>
      </ToastProvider>
    </PrefsProvider>
  );
}
