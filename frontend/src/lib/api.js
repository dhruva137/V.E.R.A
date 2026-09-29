/* The one way the dashboard talks to the engine.
 *
 * Same origin: the Vite dev server proxies /api to the engine, and in
 * production the engine serves this bundle itself. So the session cookie
 * travels with every call and there is no CORS to reason about. A 401 on
 * anything but the sign-in routes means the session ended; the auth layer
 * listens for that and shows the sign-in screen, keeping the page underneath.
 */

const BASE = import.meta.env.VITE_API_URL || '/api';

export class ApiError extends Error {
  constructor(status, detail, remedy) {
    super(detail || `Request failed (${status})`);
    this.status = status;
    this.remedy = remedy || '';
  }
}

export async function api(path, { method = 'GET', body, signal, raw = false } = {}) {
  const isForm = typeof FormData !== 'undefined' && body instanceof FormData;
  const response = await fetch(BASE + path, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined && !isForm ? { 'Content-Type': 'application/json' } : undefined,
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    signal,
  });
  if (response.status === 401 && !path.startsWith('/auth/')) {
    window.dispatchEvent(new CustomEvent('vera:signed-out'));
  }
  if (!response.ok) {
    let detail = response.statusText;
    let remedy = '';
    try {
      const payload = await response.json();
      detail = typeof payload.detail === 'string' ? payload.detail : payload.error || JSON.stringify(payload.detail ?? payload);
      remedy = payload.remedy || '';
    } catch {
      /* not JSON: keep the status text */
    }
    throw new ApiError(response.status, detail, remedy);
  }
  if (raw) return response;
  const type = response.headers.get('content-type') || '';
  return type.includes('json') ? response.json() : response.text();
}

export const get = (path, options) => api(path, options);
export const post = (path, body = {}, options) => api(path, { ...options, method: 'POST', body });
export const put = (path, body = {}, options) => api(path, { ...options, method: 'PUT', body });
export const patch = (path, body = {}, options) => api(path, { ...options, method: 'PATCH', body });
export const del = (path, options) => api(path, { ...options, method: 'DELETE' });

/* Save a response from the engine as a file on this machine. */
export async function download(path, filename) {
  const response = await api(path, { raw: true });
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') || '';
  const named = /filename="?([^";]+)"?/i.exec(disposition)?.[1];
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename || named || 'vera-export';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
