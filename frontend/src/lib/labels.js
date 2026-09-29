/* Plain names for engine keys, shared by every screen that shows them. */

export const NEED = {
  key_exchange: 'Key exchange in transit',
  kem_at_rest: 'Key wrapping at rest',
  signature_high_volume: 'Signatures, high volume',
  signature_long_lived: 'Signatures, long-lived',
  symmetric: 'Symmetric key length',
  hash: 'Hash function',
  replace_now: 'Broken: replace now',
  library_upgrade: 'Library upgrade',
  secret_exposure: 'Private key in an artefact',
  resolve_first: 'Resolve the algorithm first',
  '': 'Nothing needed',
};

export const OWNER = {
  self_managed: 'Owning team',
  vendor_firmware_gated: 'Waits on HSM vendor',
  provider_gated: 'Waits on cloud provider',
  third_party: 'Third party',
  '': 'Nobody: nothing to do',
};

export const PLANE = {
  declared: 'Declared (configuration)',
  built: 'Built (code and artefacts)',
  held: 'Held (keystores, HSM, KMS)',
  observed: 'Observed (network)',
};

export const SOURCE = {
  tls: 'Network (TLS)', ssh: 'Network (SSH)', config: 'Configuration', keystore: 'Keystore or key manager',
  source: 'Source code', dependency: 'Dependency', container: 'Container image', binary: 'Binary',
};

/* Engine-side page names (notifications, the assistant) and where they live now. */
export const ROUTE_FOR = {
  dashboard: '/overview', overview: '/overview', assets: '/inventory', inventory: '/inventory',
  dependencies: '/risk/dependencies', blast_radius: '/risk/dependencies', scanner: '/scan', discovery: '/scan',
  roadmap: '/plan/timeline', programme: '/plan/timeline', engine: '/evidence/method', cbom: '/evidence/reports',
  report: '/evidence/reports', board_memo: '/evidence/reports', settings: '/settings/runtime',
  risk: '/risk/exposure', recommendations: '/plan/actions', drift: '/risk/drift', evidence: '/evidence/integrity',
  analytics: '/risk/scores', heatmap: '/risk/scores',
};

export function routeFor(link) {
  if (!link) return '/overview';
  if (link.startsWith('/')) return link;
  const [page, query] = link.split('?');
  return `${ROUTE_FOR[page] || '/overview'}${query ? `?${query}` : ''}`;
}
