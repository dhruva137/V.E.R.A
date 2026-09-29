/* Sign in, or create the first admin on a fresh install.
 *
 * Accounts live on this machine (engine/auth.py). The first admin can only be
 * created from the machine running V.E.R.A.; after that, admins add people in
 * Settings, Users and roles.
 */

import { useState } from 'react';
import { Lock, PlayCircle } from 'lucide-react';
import Mark from '../components/Mark';
import { Button, Callout, Seg } from '../components/ui';
import { useAuth } from '../lib/auth';
import { usePrefs, useT } from '../lib/prefs';

export default function SignIn() {
  const auth = useAuth();
  const t = useT();
  const { prefs, set } = usePrefs();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const creating = auth.bootstrap;
  const demo = async () => {
    setError(null);
    setBusy(true);
    try { await auth.demoSignIn(); } catch (e) { setError(e); } finally { setBusy(false); }
  };

  const submit = async (event) => {
    event.preventDefault();
    setError(null);
    if (creating && password !== repeat) {
      setError({ message: 'The two passwords differ.' });
      return;
    }
    setBusy(true);
    try {
      if (creating) await auth.bootstrap(username, password, displayName);
      else await auth.signIn(username, password);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', placeItems: 'center', padding: 'var(--s-4)' }}>
      <main className="card" style={{ width: 'min(26rem, 100%)' }} aria-labelledby="signin-title">
        <div className="card-body stack-lg" style={{ padding: 'var(--s-6)' }}>
          <div className="row" style={{ gap: 'var(--s-3)' }}>
            <Mark size={36} />
            <div>
              <div className="strong" style={{ fontSize: 'var(--fs-18)', letterSpacing: '0.04em' }}>V.E.R.A.</div>
              <div className="small muted">Cryptographic inventory and post-quantum planning</div>
            </div>
          </div>
          <div className="stack" style={{ gap: 'var(--s-1)' }}>
            <h1 id="signin-title" style={{ fontSize: 'var(--fs-22)' }}>{creating ? t('auth.bootstrap') : t('auth.signIn')}</h1>
            <p className="small soft">
              {creating
                ? 'This is a new installation. The account you create here is the administrator; it adds everyone else.'
                : 'Use the account an administrator created for you on this machine.'}
            </p>
          </div>
          <form className="stack" onSubmit={submit} noValidate>
            <div className="field">
              <label htmlFor="u">{t('auth.username')}</label>
              <input id="u" className="input" autoComplete="username" value={username} required autoFocus
                onChange={(e) => setUsername(e.target.value)} />
            </div>
            {creating && (
              <div className="field">
                <label htmlFor="n">Full name</label>
                <input id="n" className="input" autoComplete="name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
              </div>
            )}
            <div className="field">
              <label htmlFor="p">{t('auth.password')}</label>
              <input id="p" className="input" type="password" autoComplete={creating ? 'new-password' : 'current-password'}
                value={password} required onChange={(e) => setPassword(e.target.value)} aria-describedby={creating ? 'p-hint' : undefined} />
              {creating && <span id="p-hint" className="hint">At least 12 characters. A few ordinary words together work well.</span>}
            </div>
            {creating && (
              <div className="field">
                <label htmlFor="r">Repeat password</label>
                <input id="r" className="input" type="password" autoComplete="new-password" value={repeat}
                  onChange={(e) => setRepeat(e.target.value)} />
              </div>
            )}
            {error && <Callout tone="bad" title={error.message}>{error.remedy}</Callout>}
            <Button type="submit" variant="primary" size="lg" icon={Lock} busy={busy} disabled={!username || !password}>
              {creating ? t('auth.bootstrap') : t('auth.signIn')}
            </Button>
          </form>
          {auth.demo && (
            <div className="stack" style={{ gap: 'var(--s-2)', paddingTop: 'var(--s-4)', borderTop: '1px solid var(--line)' }}>
              <Button size="lg" icon={PlayCircle} onClick={demo} disabled={busy}>Explore the demo</Button>
              <p className="xsmall muted">No password. You sign in as the demo {auth.demoRole || 'analyst'} on this machine, which
                can scan and read everything but not change settings. The operator turned this on with run.ps1 -Demo.</p>
            </div>
          )}
          <div className="row small muted" style={{ justifyContent: 'space-between' }}>
            <span>Accounts stay on this machine.</span>
            <Seg label={t('top.language')} value={prefs.lang} onChange={(lang) => set({ lang })}
              options={[{ value: 'en', label: 'EN' }, { value: 'hi', label: 'हि' }]} />
          </div>
        </div>
      </main>
    </div>
  );
}
