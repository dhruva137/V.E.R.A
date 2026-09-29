/* Who is signed in, and what their role lets them do.
 *
 * The engine enforces roles on every call (api/auth.py); the dashboard reads
 * the same capability matrix (GET /api/auth/roles) only to leave out controls a
 * person cannot use. A viewer sees no "Run scan" button rather than a button that
 * fails. `can()` takes a capability: read, audit, collaborate, scan, approve,
 * operate or admin.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { get, post } from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ loading: true, auth: true, user: null, bootstrap: false, error: null });
  const [matrix, setMatrix] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const status = await get('/auth/status');
      setState({ loading: false, auth: status.auth, user: status.user, bootstrap: status.bootstrap_required,
        demo: Boolean(status.demo), demoRole: status.demo_role, error: null });
    } catch (error) {
      setState((now) => ({ ...now, loading: false, error }));
    }
  }, []);

  useEffect(() => {
    refresh();
    const onSignedOut = () => setState((now) => (now.auth ? { ...now, user: null } : now));
    window.addEventListener('vera:signed-out', onSignedOut);
    return () => window.removeEventListener('vera:signed-out', onSignedOut);
  }, [refresh]);

  useEffect(() => {
    if (!state.user) return;
    get('/auth/roles').then((m) => setMatrix(Object.fromEntries(m.capabilities.map((c) => [c.key, c.roles]))))
      .catch(() => setMatrix(null));
  }, [state.user?.role]);

  const value = useMemo(() => ({
    ...state,
    refresh,
    signIn: async (username, password) => {
      const { user } = await post('/auth/login', { username, password });
      setState((now) => ({ ...now, user, bootstrap: false }));
    },
    demoSignIn: async () => {
      const { user } = await post('/auth/demo');
      setState((now) => ({ ...now, user }));
    },
    bootstrap: async (username, password, displayName) => {
      const { user } = await post('/auth/bootstrap', { username, password, display_name: displayName });
      setState((now) => ({ ...now, user, bootstrap: false }));
    },
    signOut: async () => {
      await post('/auth/logout');
      setState((now) => ({ ...now, user: now.auth ? null : now.user }));
    },
    can: (capability) => Boolean(state.user && matrix?.[capability]?.includes(state.user.role)),
  }), [state, refresh, matrix]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
