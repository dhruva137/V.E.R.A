/* The scan in progress, shared by the Scan screen and the top bar.
 *
 * A scan is a job on the engine that reports each step as a server-sent event
 * (/api/scan/jobs/{id}/events): each collector starting and finishing per
 * target, then identity resolution, drift, done. The top bar shows a progress
 * ring from anywhere in the app, and when the job finishes every screen's data
 * is marked stale and refreshes in place. A reload during a scan picks the job
 * up again from the engine.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { get, post } from './api';
import { invalidate } from './data';

const BASE = import.meta.env.VITE_API_URL || '/api';
const ScanContext = createContext(null);
const EVENT_TYPES = ['started', 'collector_started', 'collector_finished', 'collector_failed', 'resolved', 'drift', 'done', 'failed'];

export function summarise(events) {
  const plan = events.find((e) => e.type === 'started')?.plan || [];
  const surfaces = {};
  const touch = (name) => (surfaces[name] ||= { name, runs: 0, finished: 0, running: 0, findings: 0, ms: 0, failures: [], fatal: 0 });
  for (const target of plan) for (const collector of target.collectors) touch(collector).runs += 1;
  for (const e of events) {
    if (e.type === 'collector_started') touch(e.collector).running += 1;
    if (e.type === 'collector_finished') {
      const s = touch(e.collector);
      s.running = Math.max(0, s.running - 1);
      s.finished += 1;
      s.findings += e.findings;
      s.ms += e.duration_ms || 0;
      for (const f of e.failure_sample || []) s.failures.push({ target: f.target || e.target, reason: f.reason });
    }
    if (e.type === 'collector_failed') {
      const s = touch(e.collector);
      s.running = Math.max(0, s.running - 1);
      s.finished += 1;
      s.fatal += 1;
      s.failures.push({ target: e.target, reason: e.error });
    }
  }
  const runs = Object.values(surfaces).reduce((n, s) => n + s.runs, 0);
  const finished = Object.values(surfaces).reduce((n, s) => n + s.finished, 0);
  return {
    plan,
    surfaces: Object.values(surfaces),
    runs,
    finished,
    progress: runs ? finished / runs : 0,
    resolved: events.find((e) => e.type === 'resolved'),
    drift: events.find((e) => e.type === 'drift'),
    done: events.find((e) => e.type === 'done'),
    failed: events.find((e) => e.type === 'failed'),
  };
}

export function ScanProvider({ children }) {
  const [job, setJob] = useState(null);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const source = useRef(null);

  const follow = useCallback((jobId) => {
    source.current?.close();
    setEvents([]);
    const stream = new EventSource(`${BASE}/scan/jobs/${jobId}/events`);
    source.current = stream;
    for (const type of EVENT_TYPES) {
      stream.addEventListener(type, (message) => {
        const event = JSON.parse(message.data);
        setEvents((now) => (now.some((e) => e.seq === event.seq) ? now : [...now, event]));
        if (type === 'done' || type === 'failed') {
          stream.close();
          setJob((now) => (now ? { ...now, status: type } : now));
          if (type === 'done') invalidate('');
        }
      });
    }
    stream.onerror = () => {
      /* The browser retries on its own; a finished job closes the stream itself. */
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    get('/scan/jobs')
      .then((jobs) => {
        const running = jobs.find((j) => j.status === 'running' || j.status === 'queued');
        if (running && !cancelled) {
          setJob({ job_id: running.job_id, status: running.status, targets: running.targets.length });
          follow(running.job_id);
        }
      })
      .catch(() => { /* not signed in yet, or no scan: nothing to resume */ });
    return () => {
      cancelled = true;
      source.current?.close();
    };
  }, [follow]);

  const start = useCallback(async (request) => {
    setError(null);
    try {
      const started = await post('/scan/full', { ...request, wait: false });
      setJob({ job_id: started.job_id, status: 'running', targets: started.targets, estate: started.estate });
      follow(started.job_id);
      return started;
    } catch (e) {
      setError(e);
      throw e;
    }
  }, [follow]);

  const value = useMemo(() => {
    const summary = summarise(events);
    const running = Boolean(job) && !summary.done && !summary.failed && job.status !== 'done' && job.status !== 'failed';
    return { job, events, summary, running, error, start };
  }, [job, events, error, start]);

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  return useContext(ScanContext);
}
