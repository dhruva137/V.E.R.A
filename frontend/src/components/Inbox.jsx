/* The top-bar inbox: what needs a decision, and what changed.
 *
 *   Waiting for approval   changes the assistant proposed (GET /api/agent/proposals).
 *                          An analyst approves or rejects them here.
 *   This estate            expiries, drift, scan results (GET /api/notifications)
 *   Regulation             dated regulatory updates, each with its source; can be dismissed
 */

import { Bell, Check, X } from 'lucide-react';
import { post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, useResource } from '../lib/data';
import { date } from '../lib/format';
import { routeFor } from '../lib/labels';
import { navigate } from '../lib/router';
import { Badge, Button, Menu, useToast } from './ui';

const TONE = { critical: 'bad', high: 'warn', warning: 'warn', medium: 'info', info: 'info', low: 'neutral' };

export default function Inbox() {
  const auth = useAuth();
  const toast = useToast();
  const notes = useResource('/notifications');
  const proposals = useResource('/agent/proposals');
  const pending = (proposals.data?.proposals || []).filter((p) => !p.status || p.status === 'pending');
  const items = notes.data?.items || [];
  const urgent = items.filter((n) => n.severity === 'critical').length + pending.length;

  const decide = async (id, verb) => {
    try {
      await post(`/agent/proposals/${id}/${verb}`);
      invalidate('/agent/proposals');
      if (verb === 'approve') invalidate('');
      toast(verb === 'approve' ? 'Approved and applied.' : 'Rejected. Nothing changed.');
    } catch (e) { toast(e.message); }
  };
  const dismiss = async (id) => {
    try { await post(`/announcements/${id.replace(/^announcement-/, '')}/dismiss`); invalidate('/notifications'); }
    catch (e) { toast(e.message); }
  };

  const estate = items.filter((n) => !n.id.startsWith('announcement-'));
  const regulation = items.filter((n) => n.id.startsWith('announcement-'));
  const row = (n, canDismiss) => (
    <div key={n.id} className="menu-item" style={{ alignItems: 'flex-start', cursor: 'default', flexDirection: 'column', gap: 4 }}>
      <div className="row" style={{ width: '100%' }}>
        <Badge tone={TONE[n.severity] || 'neutral'}>{n.severity}</Badge>
        <span className="xsmall muted grow">{n.source} · {date(n.occurred_at)}</span>
        {canDismiss && <button type="button" className="link-btn xsmall" onClick={() => dismiss(n.id)}>Dismiss</button>}
      </div>
      <button type="button" className="link-btn strong" style={{ textAlign: 'left', color: 'var(--text)' }} data-close
        onClick={() => navigate(routeFor(n.deep_link))}>{n.title}</button>
      <span className="xsmall soft" style={{ whiteSpace: 'normal' }}>{n.body}</span>
    </div>
  );

  return (
    <Menu label="Inbox" trigger={(props) => (
      <button type="button" className="btn btn-quiet btn-icon" onClick={props.toggle} aria-expanded={props['aria-expanded']}
        aria-haspopup="menu"
        aria-label={urgent > 0
          ? `Inbox: ${urgent} need attention. ${pending.length} waiting for approval, ${items.length} updates. Open inbox.`
          : `Inbox: ${pending.length} waiting for approval, ${items.length} updates. Open inbox.`}
        style={{ position: 'relative' }}>
        <Bell size={16} aria-hidden />
        {urgent > 0 && <span className="count-dot" aria-hidden>{urgent > 9 ? '9+' : urgent}</span>}
      </button>
    )}>
      <div style={{ width: '26rem', maxHeight: '70vh', overflowY: 'auto' }}>
        <div className="menu-label">Waiting for approval ({pending.length})</div>
        {!pending.length && <div className="menu-item xsmall muted" style={{ cursor: 'default' }}>Nothing is waiting. Changes the assistant proposes appear here.</div>}
        {pending.map((p) => (
          <div key={p.id} className="menu-item" style={{ flexDirection: 'column', alignItems: 'flex-start', cursor: 'default', gap: 6 }}>
            <span className="strong small" style={{ whiteSpace: 'normal' }}>{p.summary}</span>
            <span className="xsmall muted">Proposed by the assistant · expires {date(p.expires_at)}</span>
            {auth.can('approve') ? (
              <div className="row">
                <Button size="sm" variant="primary" icon={Check} onClick={() => decide(p.id, 'approve')}>Approve</Button>
                <Button size="sm" icon={X} onClick={() => decide(p.id, 'reject')}>Reject</Button>
              </div>
            ) : <span className="xsmall muted">An analyst or admin decides.</span>}
          </div>
        ))}
        <hr />
        <div className="menu-label">This estate ({estate.length})</div>
        {estate.map((n) => row(n, false))}
        <hr />
        <div className="menu-label">Regulation ({regulation.length})</div>
        {regulation.map((n) => row(n, auth.can('approve')))}
      </div>
    </Menu>
  );
}
