/* The assistant: a panel beside the screen, never a screen of its own.
 *
 * It answers from the engine through its tools and shows each tool it calls,
 * so a person can see where an answer came from. In NTRO mode it is read-only
 * and runs on the local model; a change it proposes in approval mode appears
 * here as a card that an analyst approves or rejects. When it opens a screen
 * for you, the app moves and the panel stays.
 */

import { useEffect, useRef, useState } from 'react';
import { Bot, Check, CircleStop, FolderKanban, Maximize2, Minimize2, Plus, Send, Wrench, X } from 'lucide-react';
import { get, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, useResource } from '../lib/data';
import { useT } from '../lib/prefs';
import { routeFor } from '../lib/labels';
import { useCurrentProject } from '../lib/project';
import { Link, navigate, openAsset } from '../lib/router';
import { Button, Callout } from './ui';

const BASE = import.meta.env.VITE_API_URL || '/api';

const SUGGESTIONS = [
  'What should we fix first, and why?',
  'Which assets cannot meet their DST milestone?',
  'Which suppliers are blocking our migration?',
  'Explain the highest-priority asset.',
];

/* Enough Markdown for an answer: paragraphs, lists, bold and code. Rendered as
 * React elements, never as HTML, so a model's output cannot inject markup. */
function inline(text) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={i}>{part.slice(2, -2)}</strong>;
    if (part.startsWith('`') && part.endsWith('`')) return <code key={i}>{part.slice(1, -1)}</code>;
    return part;
  });
}

function Answer({ text }) {
  const blocks = [];
  let list = null;
  for (const line of String(text || '').split('\n')) {
    const item = /^\s*(?:[-*•]|\d+\.)\s+(.*)$/.exec(line);
    if (item) {
      if (!list) { list = []; blocks.push({ list }); }
      list.push(item[1]);
    } else {
      list = null;
      if (line.trim()) blocks.push({ p: line.replace(/^#+\s*/, '') });
    }
  }
  return (
    <div className="msg msg-assistant">
      {blocks.map((b, i) => (b.list ? (
        <ul key={i} style={{ paddingLeft: '1.25rem', margin: 'var(--s-2) 0' }}>
          {b.list.map((li, j) => <li key={j}>{inline(li)}</li>)}
        </ul>
      ) : <p key={i}>{inline(b.p)}</p>))}
    </div>
  );
}

function Proposal({ proposal, canApprove }) {
  const [state, setState] = useState('pending');
  const [error, setError] = useState(null);
  const decide = async (verb) => {
    try {
      await post(`/agent/proposals/${proposal.proposal_id}/${verb}`);
      setState(verb === 'approve' ? 'approved' : 'rejected');
      if (verb === 'approve') invalidate('');
    } catch (e) {
      setError(e);
    }
  };
  return (
    <div className="card card-pad stack" style={{ gap: 'var(--s-2)' }}>
      <div className="strong">Proposed change: needs approval</div>
      <p className="small">{proposal.summary}</p>
      <p className="xsmall muted">{proposal.assets_affected} asset(s). Nothing has changed yet.</p>
      {state === 'pending' ? (canApprove ? (
        <div className="row">
          <Button size="sm" variant="primary" icon={Check} onClick={() => decide('approve')}>Approve</Button>
          <Button size="sm" icon={X} onClick={() => decide('reject')}>Reject</Button>
        </div>
      ) : <p className="xsmall muted">A risk owner, analyst or admin must approve this.</p>) : (
        <p className="small strong">{state === 'approved' ? 'Approved and applied.' : 'Rejected. Nothing changed.'}</p>
      )}
      {error && <p className="small" style={{ color: 'var(--bad-text)' }}>{error.message}</p>}
    </div>
  );
}

export default function Assistant({ onClose, full = false, onToggleFull }) {
  const t = useT();
  const auth = useAuth();
  const status = useResource('/agent/status');
  const [transcript, setTranscript] = useState([]);
  const [items, setItems] = useState([]);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const log = useRef(null);
  const abort = useRef(null);
  // Conversations are kept per project (engine/projects.py), so a job's reasoning can be resumed and handed over.
  const project = useCurrentProject();
  const canKeep = auth.can('collaborate');
  const threads = useResource(canKeep ? `/threads${project ? `?project=${project.id}` : ''}` : null);
  const [threadId, setThreadId] = useState(null);

  const startNew = () => { setThreadId(null); setTranscript([]); setItems([]); setError(null); };
  useEffect(startNew, [project?.id]);

  const openThread = async (id) => {
    if (!id) { startNew(); return; }
    const t = await get(`/threads/${id}`);
    setThreadId(id);
    setTranscript(t.messages);
    setItems(t.messages.map((m) => ({ kind: m.role === 'user' ? 'user' : 'assistant', text: m.content })));
  };

  const keep = async (messages) => {
    if (!canKeep || !messages.length) return;
    const body = { project_id: project?.id || null, messages };
    const saved = threadId ? await put(`/threads/${threadId}`, body) : await post('/threads', body);
    setThreadId(saved.id);
    invalidate('/threads');
    invalidate('/projects');
  };

  useEffect(() => { log.current?.scrollTo({ top: log.current.scrollHeight, behavior: 'smooth' }); }, [items]);

  const act = (result) => {
    if (result?.action === 'navigate') {
      const to = result.route || routeFor(result.page);
      navigate(to);
      if (result.focus_asset_id) setTimeout(() => openAsset(result.focus_asset_id), 0);
    }
  };

  const send = async (text) => {
    const content = text.trim();
    if (!content || busy) return;
    const messages = [...transcript, { role: 'user', content }];
    setItems((now) => [...now, { kind: 'user', text: content }]);
    setDraft('');
    setBusy(true);
    setError(null);
    const controller = new AbortController();
    abort.current = controller;
    try {
      const response = await fetch(`${BASE}/chat/stream`, {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages }), signal: controller.signal,
      });
      if (response.status === 401) window.dispatchEvent(new CustomEvent('vera:signed-out'));
      if (!response.ok || !response.body) {
        let detail = response.statusText;
        try { detail = (await response.json()).detail || detail; } catch { /* keep status text */ }
        throw new Error(detail);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let final = null;
      const handle = (type, data) => {
        if (type === 'tool_call') setItems((now) => [...now, { kind: 'step', text: `Using ${data.name.replace(/_/g, ' ')}` }]);
        if (type === 'tool_result') {
          act(data.result);
          if (data.result?.status === 'awaiting_approval') setItems((now) => [...now, { kind: 'proposal', proposal: data.result }]);
        }
        if (type === 'message' && data.message?.content) setItems((now) => [...now, { kind: 'assistant', text: data.message.content }]);
        if (type === 'error') setError(new Error(`${data.error} ${data.remedy || ''}`));
        if (type === 'done') final = data.payload ?? data;
      };
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let cut = buffer.indexOf('\n\n');
        while (cut !== -1) {
          const frame = buffer.slice(0, cut);
          buffer = buffer.slice(cut + 2);
          let type = 'message';
          const data = [];
          for (const line of frame.split('\n')) {
            if (line.startsWith('event:')) type = line.slice(6).trim();
            else if (line.startsWith('data:')) data.push(line.slice(5).trim());
          }
          if (data.length) {
            try { handle(type, JSON.parse(data.join('\n'))); } catch { /* skip a frame that is not JSON */ }
          }
          cut = buffer.indexOf('\n\n');
        }
      }
      if (final?.messages) {
        const kept = final.messages.filter((m) => m.role === 'user' || m.role === 'assistant');
        setTranscript(kept);
        keep(kept).catch(() => { /* the answer stands; keeping it is best effort and never blocks the conversation */ });
      }
    } catch (e) {
      if (e.name !== 'AbortError') setError(e);
    } finally {
      setBusy(false);
      abort.current = null;
    }
  };

  const llm = status.data?.llm;
  const mode = status.data?.settings?.mode;
  return (
    <aside className={full ? 'assist assist-full' : 'assist'} aria-label={t('top.assistant')}
      onKeyDown={(e) => { if (full && e.key === 'Escape') onToggleFull(); }}>
      <div className="assist-head">
        <Bot size={18} aria-hidden />
        <div className="grow">
          <div className="strong">{t('top.assistant')}</div>
          <div className="xsmall muted">
            {llm?.is_configured ? `${llm.model} · local` : 'Answers from the engine; no model configured'}
            {mode ? ` · ${mode.replace('_', '-')}` : ''}
          </div>
        </div>
        <Button variant="quiet" icon={full ? Minimize2 : Maximize2} aria-pressed={full}
          aria-label={full ? 'Show as a side panel' : 'Open full screen'} title={full ? 'Side panel' : 'Full screen'}
          onClick={onToggleFull} />
        <Button variant="quiet" icon={X} aria-label={t('common.close')} onClick={onClose} />
      </div>
      <div className="assist-threads">
        <FolderKanban size={14} aria-hidden />
        {project ? <Link to={`/projects/${project.id}`} className="xsmall strong truncate">{project.name}</Link>
          : <Link to="/projects" className="xsmall muted">No project: pick one to keep conversations</Link>}
        {canKeep && (
          <select className="select select-sm grow" aria-label="Conversation" value={threadId || ''} onChange={(e) => openThread(e.target.value)}>
            <option value="">New conversation</option>
            {(threads.data || []).map((th) => <option key={th.id} value={th.id}>{th.title}</option>)}
          </select>
        )}
        {canKeep && <Button size="sm" variant="quiet" icon={Plus} aria-label="New conversation" title="New conversation" onClick={startNew} />}
      </div>
      <div ref={log} className="assist-log" aria-live="polite">
        {!items.length && (
          <div className="stack">
            <p className="small soft">Ask about this estate. Each answer shows the tools it used, and every figure comes from the
              engine, not from the model's memory.</p>
            {SUGGESTIONS.map((s) => (
              <button key={s} type="button" className="btn btn-sm" style={{ justifyContent: 'flex-start', height: 'auto', padding: 'var(--s-2) var(--s-3)', whiteSpace: 'normal', textAlign: 'left' }}
                onClick={() => send(s)}>{s}</button>
            ))}
          </div>
        )}
        {items.map((item, i) => {
          if (item.kind === 'user') return <div key={i} className="msg msg-user">{item.text}</div>;
          if (item.kind === 'step') return <div key={i} className="msg-step"><Wrench size={12} aria-hidden />{item.text}</div>;
          if (item.kind === 'proposal') return <Proposal key={i} proposal={item.proposal} canApprove={auth.can('approve')} />;
          return <Answer key={i} text={item.text} />;
        })}
        {busy && <div className="msg-step"><span className="dot dot-primary" aria-hidden /> Working…</div>}
        {error && <Callout tone="bad" title="The assistant stopped.">{error.message}</Callout>}
      </div>
      <form className="assist-form" onSubmit={(e) => { e.preventDefault(); send(draft); }}>
        <label htmlFor="assist-input" className="sr-only">Message the assistant</label>
        <textarea id="assist-input" className="textarea" value={draft} onChange={(e) => setDraft(e.target.value)}
          placeholder="Ask a question about this estate" rows={2}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(draft); } }} />
        <div className="row">
          <span className="xsmall muted grow">Enter sends · Shift+Enter for a new line</span>
          {busy ? (
            <Button size="sm" icon={CircleStop} onClick={() => abort.current?.abort()}>Stop</Button>
          ) : (
            <Button size="sm" variant="primary" icon={Send} type="submit" disabled={!draft.trim()}>Send</Button>
          )}
        </div>
      </form>
    </aside>
  );
}
