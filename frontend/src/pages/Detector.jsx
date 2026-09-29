/* Evidence -> Detector: the certified binary detector, shown with its own numbers.
 *
 * Everything on this screen is /api/detector, which reads research/results/*.json and names the file and commit
 * of each block. The alpha dial re-thresholds the stored q-values of the end-to-end programs: a program is flagged
 * at a given false-discovery level exactly when its smallest q-value is at or below it, so moving the dial shows
 * what the guarantee buys and what it costs, on real stripped binaries, with nothing recomputed in the browser
 * beyond that comparison.
 */
import { useMemo, useState } from 'react';
import { CircleCheck, CircleX, ShieldCheck } from 'lucide-react';
import { Badge, Callout, Card, Figure, Load, Skeleton } from '../components/ui';
import { useResource } from '../lib/data';
import { fmt, pct } from '../lib/format';

const pct1 = (x) => `${(100 * x).toFixed(1)}%`;

function Source({ block }) {
  return <p className="xsmall muted">Source: <code>{block.file}</code> · commit <code>{block.commit}</code></p>;
}

/* Bars drawn in plain SVG: one axis, labelled values, a dashed rule for alpha. */
function PairBars({ rows, a, b, labels, alpha, max = 1 }) {
  const W = 520;
  const H = 180;
  const bw = 34;
  const gap = W / rows.length;
  const y = (v) => H - 20 - (v / max) * (H - 40);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="det-bars" role="img"
      aria-label={rows.map((r) => `${r.label}: ${labels[0]} ${pct1(r[a])}, ${labels[1]} ${pct1(r[b])}`).join('; ')}>
      {alpha != null && (
        <g>
          <line x1="0" x2={W} y1={y(alpha)} y2={y(alpha)} className="det-alpha" />
          <text x={W - 4} y={y(alpha) - 4} textAnchor="end" className="det-axis">α = {alpha}</text>
        </g>
      )}
      {rows.map((r, i) => {
        const cx = gap * i + gap / 2;
        return (
          <g key={r.label}>
            {[a, b].map((k, j) => {
              const x = cx - bw - 2 + j * (bw + 4);
              return (
                <g key={k}>
                  <rect x={x} y={y(r[k])} width={bw} height={Math.max(1, H - 20 - y(r[k]))} rx="4" className={`det-bar det-bar-${j}`} />
                  <text x={x + bw / 2} y={y(r[k]) - 4} textAnchor="middle" className="det-val">{pct1(r[k])}</text>
                </g>
              );
            })}
            <text x={cx} y={H - 4} textAnchor="middle" className="det-axis">{r.label}</text>
          </g>
        );
      })}
    </svg>
  );
}

function Legend({ labels }) {
  return (
    <ul className="det-legend">
      {labels.map((l, i) => <li key={l}><span className={`det-sw det-bar-${i}`} aria-hidden />{l}</li>)}
    </ul>
  );
}

function Binaries({ block }) {
  const [alpha, setAlpha] = useState(block.alpha);
  const [showOverlap, setShowOverlap] = useState(false);
  const progs = useMemo(() => block.programs.filter((p) => showOverlap || !p.train_overlap), [block, showOverlap]);
  const flagged = (p) => p.signatures || p.pqc_table || (p.min_q?.v1 != null && p.min_q.v1 <= alpha);
  const pos = progs.filter((p) => p.contains_crypto);
  const neg = progs.filter((p) => !p.contains_crypto);
  const tpr = pos.filter(flagged).length / Math.max(1, pos.length);
  const fpr = neg.filter(flagged).length / Math.max(1, neg.length);
  const learnedOnly = pos.filter((p) => !p.signatures && !p.pqc_table && p.min_q?.v1 <= alpha).length;
  return (
    <Card title="Research protocol: move α" pad={false}
      description="The research evaluation of the same model design (a refit with identical features), which stores every program's smallest q-value so α can be moved. Quote the shipped numbers above; this shows how the trade-off moves. Each program is built static and stripped; ground truth comes from the unstripped twin.">
      <div className="det-dial">
        <label htmlFor="alpha" className="strong">False-discovery level α</label>
        <input id="alpha" type="range" min="0.01" max="0.3" step="0.01" value={alpha}
          onChange={(e) => setAlpha(Number(e.target.value))} aria-valuetext={`alpha ${alpha}`} />
        <span className="num strong det-alpha-val">{alpha.toFixed(2)}</span>
        <label className="check small"><input type="checkbox" checked={showOverlap} onChange={(e) => setShowOverlap(e.target.checked)} />
          Include programs built from training libraries</label>
      </div>
      <div className="grid-3 det-figs">
        <Figure label="Crypto programs detected" value={pct(100 * tpr)} detail={`${pos.filter(flagged).length} of ${pos.length}`}
          source="Signature layers, PQC table layer, or certified learned layer" />
        <Figure label="False alarms" value={pct(100 * fpr)} detail={`${neg.filter(flagged).length} of ${neg.length} non-crypto programs`}
          source="A program is flagged when any layer fires" />
        <Figure label="Found only by the learned layer" value={fmt(learnedOnly)} detail="crypto programs no signature explains"
          source={`Certified at α = ${alpha.toFixed(2)}, per-ISA calibration`} />
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Program</th><th>ISA</th><th>Truth</th><th>Signatures</th><th>PQC table</th><th className="r">Learned: smallest q</th><th>Verdict at α</th></tr></thead>
          <tbody>
            {progs.map((p) => {
              const f = flagged(p);
              const right = f === p.contains_crypto;
              const q = p.min_q?.v1;
              return (
                <tr key={p.name}>
                  <td className="strong">{p.name.replace(/_(x86_64|aarch64)$/, '')}{p.train_overlap && <span className="xsmall muted"> · training library</span>}</td>
                  <td className="small">{p.arch}</td>
                  <td>{p.contains_crypto ? <Badge tone="info">crypto</Badge> : <Badge tone="neutral">no crypto</Badge>}</td>
                  <td>{p.signatures ? <Badge tone="primary">fired</Badge> : <span className="muted small">silent</span>}</td>
                  <td>{p.pqc_table ? <Badge tone="primary">ML-KEM/ML-DSA</Badge> : <span className="muted small">—</span>}</td>
                  <td className="r num">{q == null ? '—' : <span className={q <= alpha ? 'strong' : 'muted'}>{q < 0.001 ? '< 0.001' : q.toFixed(3)}</span>}</td>
                  <td>{right
                    ? <span className="row small det-ok"><CircleCheck size={14} aria-hidden />{f ? 'flagged, correct' : 'clear, correct'}</span>
                    : <span className="row small det-bad"><CircleX size={14} aria-hidden />{f ? 'false alarm' : 'missed'}</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="card-foot">
        A program's smallest q-value is the lowest false-discovery level at which its most crypto-like function is still
        selected. Calibration: {Object.entries(block.calibration_n).map(([k, n]) => `${fmt(n)} non-crypto functions (${k})`).join(', ')}.
        <Source block={block} />
      </div>
    </Card>
  );
}

const LAYER = { constant: 'constant table', symbol: 'symbol', version_banner: 'version banner', pqc_table: 'PQC table',
  learned_function: 'learned, certified' };

/* The shipped model and calibration through the product's own scan path, at the shipped alpha. Fixed, not a dial:
   the product records a q-value only for what it selects, so re-thresholding above alpha would need numbers it does
   not keep. */
function Shipped({ block }) {
  const s = block.summary;
  const progs = block.programs.filter((p) => !p.train_overlap);
  return (
    <Card title="As shipped: the product scan path" pad={false}
      description="The same stripped, statically linked programs, scanned by the shipped model and calibration exactly as a user's scan runs.">
      <div className="grid-3 det-figs">
        <Figure label="Crypto programs detected" value={`${s.detected} of ${s.positives}`} detail="any layer fired"
          source={`${block.file} @ ${block.commit}`} />
        <Figure label="False alarms" value={`${s.false_alarms} of ${s.negatives}`} detail="non-crypto programs flagged"
          source={`${block.file} @ ${block.commit}`} />
        <Figure label="Found only by the learned layer" value={fmt(s.found_only_by_learned_layer)}
          detail={`median ${s.median_seconds_per_binary} s per binary`} source={`${block.file} @ ${block.commit}`} />
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Program</th><th>Truth</th><th>Layers that fired</th><th>Named</th><th className="r">Learned q</th><th>Verdict</th></tr></thead>
          <tbody>
            {progs.map((p) => {
              const right = p.flagged === p.contains_crypto;
              return (
                <tr key={p.name}>
                  <td className="strong">{p.name}</td>
                  <td>{p.contains_crypto ? <Badge tone="info">crypto</Badge> : <Badge tone="neutral">no crypto</Badge>}</td>
                  <td className="small">{p.layers.length ? p.layers.map((l) => LAYER[l] || l).join(', ') : <span className="muted">none</span>}</td>
                  <td className="small">{p.algorithms.join(', ') || <span className="muted">—</span>}</td>
                  <td className="r num">{p.learned_q == null ? '—' : p.learned_q.toFixed(3)}</td>
                  <td>{right
                    ? <span className="row small det-ok"><CircleCheck size={14} aria-hidden />{p.flagged ? 'flagged, correct' : 'clear, correct'}</span>
                    : <span className="row small det-bad"><CircleX size={14} aria-hidden />{p.flagged ? 'false alarm' : 'missed'}</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="card-foot">The learned layer runs only when no other layer explains the binary, and reports a q-value only
        for functions it selects. <Source block={block} /></div>
    </Card>
  );
}

export default function Detector() {
  const res = useResource('/detector');
  return (
    <Load resource={res} skeleton={<Skeleton height="30rem" />}>
      {(d) => (
        <div className="stack-lg">
          <Callout tone="info" title="Every binary finding states its own error rate.">
            The learned layer selects cryptographic functions so that, on average, at most a chosen share α of what it
            reports is wrong, with no assumption about the model; the only assumption is that calibration code resembles
            the code under test, which is why calibration is per instruction set. Signatures run first; the learned layer
            covers what they cannot see.
          </Callout>
          {d.shipped && <Shipped block={d.shipped} />}
          {d.binaries && <Binaries block={d.binaries} />}
          <div className="grid-2">
            {d.threshold_vs_conformal && (
              <Card title="A fixed confidence cut-off is not a guarantee"
                description="Share of flagged functions that are not cryptographic, on libraries the model never saw.">
                <PairBars alpha={0.1} a="fixed_threshold_fdp" b="conformal_fdp" labels={['fixed ≥ 0.9', 'certified, α = 0.1']}
                  rows={d.threshold_vs_conformal.rows.map((r) => ({ ...r, label: r.prevalence === 'natural' ? '34% crypto' : `${pct(100 * Number(r.prevalence))} crypto` }))} />
                <Legend labels={['fixed confidence ≥ 0.9', 'certified selection, α = 0.1']} />
                <Source block={d.threshold_vs_conformal} />
              </Card>
            )}
            {d.per_isa && (
              <Card title="Calibrate per instruction set"
                description={`${d.per_isa.model}, trained on all ISAs, 5% crypto: calibrating on another ISA inflates false discoveries.`}>
                <PairBars alpha={d.per_isa.alpha} max={0.15} a="x86" b="per"
                  labels={['calibrated on x86-64', 'calibrated per ISA']}
                  rows={['x86-64', 'aarch64', 'arm32'].map((isa) => ({
                    label: isa,
                    x86: d.per_isa.matrix[`train=all/test=${isa}/calibrate=x86-64`].mean_fdp,
                    per: d.per_isa.matrix[`train=all/test=${isa}/calibrate=per-isa`].mean_fdp,
                  }))} />
                <Legend labels={['calibrated on x86-64', 'calibrated per ISA']} />
                <Source block={d.per_isa} />
              </Card>
            )}
          </div>
          <div className="grid-3">
            {d.threshold_vs_conformal && (
              <Figure label="Detection on unseen libraries" value={d.threshold_vs_conformal.sealed_roc_auc.toFixed(3)}
                detail="ROC-AUC, sealed test libraries" source="research/results/v1_1_detector.json" />
            )}
            {d.theory && (
              <Figure label="Guarantee checks" value={`${d.theory.violations} violations`}
                detail={`${d.theory.cells} simulated settings × ${fmt(d.theory.reps)} repetitions`} source={d.theory.file} />
            )}
            {d.architecture && (
              <Figure label="Model in use" value="v1 trees"
                detail={`Graph model gained ${d.architecture.ship_rule.gain.toFixed(3)} PR-AUC on sealed; the bar to ship is 0.03`}
                source={d.architecture.file} />
            )}
          </div>
          <p className="xsmall muted row"><ShieldCheck size={14} aria-hidden /> Method, proofs and every experiment: research/README.md and research/THEORY.md.</p>
        </div>
      )}
    </Load>
  );
}
