/* A small read cache: show what is known at once, refresh behind it.
 *
 * Every screen reads through `useResource(path)`. The first visit fetches; a
 * later visit renders the cached answer immediately and refreshes it, so going
 * back to a page never shows a blank screen. A finished scan marks everything
 * stale (`invalidate()`), and whatever is on screen refreshes in place without
 * a spinner. Hovering a link calls `prefetch`, so the data is usually there
 * before the click.
 */

import { useEffect, useReducer } from 'react';
import { get } from './api';

const cache = new Map(); // path -> { data, error, stale, promise, at }
const listeners = new Map(); // path -> Set<fn>

function notify(path) {
  for (const fn of listeners.get(path) || []) fn();
}

function load(path) {
  const entry = cache.get(path) || {};
  if (entry.promise) return entry.promise;
  const promise = get(path)
    .then((data) => {
      cache.set(path, { data, error: null, stale: false, promise: null, at: Date.now() });
    })
    .catch((error) => {
      cache.set(path, { ...cache.get(path), error, stale: false, promise: null, at: Date.now() });
    })
    .finally(() => notify(path));
  cache.set(path, { ...entry, promise });
  notify(path);
  return promise;
}

export function prefetch(path) {
  const entry = cache.get(path);
  if (!entry || entry.stale) load(path);
}

export function invalidate(prefix = '') {
  for (const [path, entry] of cache) {
    if (path.startsWith(prefix)) {
      cache.set(path, { ...entry, stale: true });
      notify(path);
    }
  }
}

export function setCached(path, data) {
  cache.set(path, { data, error: null, stale: false, promise: null, at: Date.now() });
  notify(path);
}

export function useResource(path, { enabled = true } = {}) {
  const [, rerender] = useReducer((n) => n + 1, 0);
  useEffect(() => {
    if (!path) return undefined;
    const set = listeners.get(path) || new Set();
    set.add(rerender);
    listeners.set(path, set);
    return () => set.delete(rerender);
  }, [path]);

  const entry = path ? cache.get(path) : undefined;
  const needsLoad = Boolean(path && enabled && (!entry || entry.stale) && !entry?.promise);
  useEffect(() => {
    if (needsLoad) load(path);
  }, [needsLoad, path]);

  return {
    data: entry?.data,
    error: entry?.error || null,
    loading: Boolean(path && enabled && (!entry || entry.promise) && entry?.data === undefined),
    refreshing: Boolean(entry?.promise && entry?.data !== undefined),
    reload: () => path && load(path),
  };
}
