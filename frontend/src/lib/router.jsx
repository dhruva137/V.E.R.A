/* Hash routing, because the engine serves one file and every view must be linkable.
 *
 *   #/inventory?status=vulnerable&asset=<id>
 *
 * The path picks the screen and its tab; the query holds filters and the open
 * asset, so a link pasted into a report opens exactly what the author saw.
 * `Link` warms the next screen on hover or focus: its code chunk and its data.
 */

import { useCallback, useEffect, useState } from 'react';

function parse() {
  const raw = window.location.hash.replace(/^#/, '') || '/overview';
  const [path, query = ''] = raw.split('?');
  const clean = path.startsWith('/') ? path : `/${path}`;
  return { path: clean, segments: clean.split('/').filter(Boolean), params: new URLSearchParams(query) };
}

export function navigate(to, { replace = false } = {}) {
  const target = `#${to.startsWith('/') ? to : `/${to}`}`;
  if (replace) window.history.replaceState(null, '', target);
  else window.history.pushState(null, '', target);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}

export function useRoute() {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const onChange = () => setRoute(parse());
    window.addEventListener('hashchange', onChange);
    window.addEventListener('popstate', onChange);
    return () => {
      window.removeEventListener('hashchange', onChange);
      window.removeEventListener('popstate', onChange);
    };
  }, []);
  return route;
}

/* Change query parameters on the current path without losing the others. */
export function useQueryParams() {
  const route = useRoute();
  const set = useCallback((changes, { replace = true } = {}) => {
    const now = parse();
    const next = new URLSearchParams(now.params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null || value === undefined || value === '') next.delete(key);
      else next.set(key, String(value));
    }
    const query = next.toString();
    navigate(`${now.path}${query ? `?${query}` : ''}`, { replace });
  }, []);
  return [route.params, set];
}

/* Opening an asset goes to its own page, so Back returns to exactly where you were. */
export function openAsset(id) {
  navigate(`/asset/${encodeURIComponent(id)}`);
}

export function Link({ to, onWarm, children, className, ...rest }) {
  const warm = () => onWarm?.();
  return (
    <a
      href={`#${to}`}
      className={className}
      onMouseEnter={warm}
      onFocus={warm}
      onClick={(event) => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
        event.preventDefault();
        navigate(to);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}
