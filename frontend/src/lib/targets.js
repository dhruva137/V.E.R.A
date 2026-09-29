/* What a scan can point at. Shared by the Scan screen and Projects so both offer the same kinds. */
export const KINDS = [
  { value: 'path', label: 'Folder on this machine' }, { value: 'repo', label: 'Git repository (path or URL)' },
  { value: 'image', label: 'Container image (tar or folder)' }, { value: 'host', label: 'Live endpoint (host:port)' },
  { value: 'capture', label: 'Recorded capture (JSON)' }, { value: 'vault', label: 'Key manager export' },
];

export const PLACEHOLDER = {
  path: 'C:\code\payments', repo: 'https://github.com/org/repo or C:\repos\app',
  image: 'C:\images\nginx.oci.tar', host: 'pay.example.in:443', capture: 'C:\captures\tls.json',
  vault: 'C:\exports\key-manager',
};

export const kindLabel = (value) => KINDS.find((k) => k.value === value)?.label || value;
