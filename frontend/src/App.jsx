import { AuthProvider, useAuth } from './lib/auth';
import { PrefsProvider } from './lib/prefs';
import { ScanProvider } from './lib/scan';
import { ToastProvider, Callout, Button } from './components/ui';
import Shell from './components/Shell';
import SignIn from './pages/SignIn';

function Gate() {
  const auth = useAuth();
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
