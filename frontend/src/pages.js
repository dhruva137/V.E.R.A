/* The six destinations and Settings.
 *
 * Each screen is its own code chunk. `warm` loads the chunk and the screen's
 * first data call, and runs when a link to it is hovered or focused, so the
 * screen is usually ready before the click lands.
 */

import { lazy } from 'react';
import { Boxes, FileCheck2, FolderKanban, LayoutDashboard, ListChecks, Radar, Settings, ShieldAlert, Sparkles } from 'lucide-react';
import { prefetch } from './lib/data';

const loaders = {
  overview: () => import('./pages/Overview.jsx'),
  scan: () => import('./pages/Scan.jsx'),
  inventory: () => import('./pages/Inventory.jsx'),
  risk: () => import('./pages/Risk.jsx'),
  plan: () => import('./pages/Plan.jsx'),
  evidence: () => import('./pages/Evidence.jsx'),
  settings: () => import('./pages/Settings.jsx'),
  asset: () => import('./pages/Asset.jsx'),
  projects: () => import('./pages/Projects.jsx'),
  why: () => import('./pages/Why.jsx'),
};

const firstData = {
  overview: ['/overview'],
  scan: ['/scan/collectors', '/scans'],
  inventory: ['/inventory'],
  risk: ['/risk'],
  plan: ['/recommendations'],
  evidence: ['/certin-conformance'],
  settings: ['/ntro-mode'],
  projects: ['/projects'],
  why: ['/detector'],
};

export const DESTINATIONS = [
  { key: 'projects', icon: FolderKanban, to: '/projects' },
  { key: 'overview', icon: LayoutDashboard, to: '/overview' },
  { key: 'scan', icon: Radar, to: '/scan' },
  { key: 'inventory', icon: Boxes, to: '/inventory' },
  { key: 'risk', icon: ShieldAlert, to: '/risk/exposure' },
  { key: 'plan', icon: ListChecks, to: '/plan/actions' },
  { key: 'evidence', icon: FileCheck2, to: '/evidence/reports' },
];
export const SETTINGS = { key: 'settings', icon: Settings, to: '/settings/runtime' };
export const WHY = { key: 'why', icon: Sparkles, to: '/why' };

export const SCREENS = Object.fromEntries(Object.entries(loaders).map(([key, load]) => [key, lazy(load)]));

export function warm(key, hasScan = true) {
  loaders[key]?.();
  if (hasScan || ['scan', 'settings', 'projects', 'why'].includes(key)) for (const path of firstData[key] || []) prefetch(path);
}
