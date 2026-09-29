/* Per-person display preferences: theme, text size, language (GIGW 3.0).
 *
 * Kept in this browser only; they change how the screen looks, never what the
 * engine computes. Storage can be unavailable (private windows, locked-down
 * profiles), so every read and write tolerates that and the defaults apply.
 *
 * Language covers the interface chrome: navigation, headings, buttons and
 * status words. Findings, evidence and citations stay in English, as recorded,
 * so that what an assessor reads matches the exported documents word for word.
 */

import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';

const KEY = 'vera.prefs.v2';
const DEFAULTS = { theme: 'light', text: 'normal', lang: 'en' };

function read() {
  try {
    return { ...DEFAULTS, ...JSON.parse(window.localStorage.getItem(KEY) || '{}') };
  } catch {
    return { ...DEFAULTS };
  }
}

function write(prefs) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage unavailable: the preference lasts for this visit only */
  }
}

const EN = {
  'nav.overview': 'Overview', 'nav.scan': 'Scan', 'nav.inventory': 'Inventory', 'nav.risk': 'Risk',
  'nav.plan': 'Plan', 'nav.evidence': 'Evidence', 'nav.settings': 'Settings',
  'nav.asset': 'Asset', 'nav.projects': 'Projects', 'nav.why': 'Why V.E.R.A.',
  'top.search': 'Search assets, pages and actions', 'top.assistant': 'Assistant', 'top.textSize': 'Text size',
  'top.theme': 'Theme', 'top.light': 'Light', 'top.dark': 'Dark', 'top.language': 'Language',
  'top.signOut': 'Sign out', 'top.signedInAs': 'Signed in as', 'top.lastScan': 'Last scan',
  'top.noScan': 'No scan yet', 'top.scanning': 'Scanning', 'top.display': 'Display',
  'common.runScan': 'Run scan', 'common.open': 'Open', 'common.close': 'Close', 'common.download': 'Download',
  'common.retry': 'Try again', 'common.source': 'Source', 'common.cancel': 'Cancel', 'common.save': 'Save',
  'common.clearFilters': 'Clear filters', 'common.skip': 'Skip to main content', 'common.all': 'All',
  'overview.doNext': 'Do next', 'overview.milestones': 'DST milestones', 'overview.systems': 'Exposure by system',
  'overview.coverage': 'Coverage and evidence', 'fig.inventoried': 'Assets inventoried',
  'fig.vulnerable': 'Quantum-vulnerable', 'fig.exposed': 'Exposed before migration', 'fig.gated': 'Blocked on suppliers',
  'status.broken': 'Broken', 'status.vulnerable': 'Vulnerable', 'status.weakened': 'Weakened', 'status.safe': 'Safe',
  'status.unresolved': 'Unresolved', 'mosca.certain': 'Exposed', 'mosca.likely': 'Likely exposed',
  'mosca.possible': 'Possibly exposed', 'mosca.clear': 'Clear', 'mosca.not_applicable': 'Not applicable',
  'risk.exposure': 'Quantum exposure', 'risk.drift': 'Policy drift', 'risk.dependencies': 'Dependencies',
  'risk.scores': 'Score analysis', 'risk.after': 'After migration', 'plan.waves': 'Waves', 'plan.simulate': 'Simulate',
  'evidence.compliance': 'Compliance', 'settings.api': 'API access',
  'plan.actions': 'Actions', 'plan.suppliers': 'Suppliers', 'plan.timeline': 'Timeline',
  'evidence.reports': 'Reports and exports', 'evidence.certin': 'CERT-In conformance', 'evidence.integrity': 'Integrity',
  'evidence.changes': 'Changes', 'evidence.detector': 'Detector', 'evidence.method': 'Method',
  'settings.runtime': 'Runtime', 'settings.users': 'Users and roles', 'settings.model': 'Assistant model',
  'settings.policy': 'Profile and policy', 'settings.access': 'Accessibility and language',
  'panel.summary': 'Summary', 'panel.evidence': 'Evidence', 'panel.risk': 'Quantum risk', 'panel.fix': 'Fix',
  'panel.dependencies': 'Dependencies', 'panel.history': 'History',
  'auth.signIn': 'Sign in', 'auth.username': 'Username', 'auth.password': 'Password',
  'auth.bootstrap': 'Create the first admin', 'role.admin': 'Admin', 'role.analyst': 'Analyst', 'role.viewer': 'Viewer',
  'overview.report': 'Assessment report (PDF)', 'common.scanAgain': 'Scan again', 'overview.allActions': 'All actions',
  'ms.met': 'Met', 'ms.in_progress': 'In progress', 'ms.at_risk': 'At risk', 'ms.missed': 'Missed',
  'common.export': 'Export these rows (CSV)', 'common.search': 'Search',
};

const HI = {
  'nav.overview': 'अवलोकन', 'nav.scan': 'स्कैन', 'nav.inventory': 'सूची', 'nav.risk': 'जोखिम',
  'nav.plan': 'योजना', 'nav.evidence': 'साक्ष्य', 'nav.settings': 'सेटिंग्स',
  'nav.asset': 'परिसंपत्ति', 'nav.projects': 'परियोजनाएँ', 'nav.why': 'V.E.R.A. क्यों',
  'top.search': 'परिसंपत्तियाँ, पृष्ठ और कार्य खोजें', 'top.assistant': 'सहायक', 'top.textSize': 'अक्षर का आकार',
  'top.theme': 'रंग-रूप', 'top.light': 'हल्का', 'top.dark': 'गहरा', 'top.language': 'भाषा',
  'top.signOut': 'साइन आउट करें', 'top.signedInAs': 'इस नाम से साइन इन', 'top.lastScan': 'पिछला स्कैन',
  'top.noScan': 'अभी तक कोई स्कैन नहीं', 'top.scanning': 'स्कैन हो रहा है', 'top.display': 'प्रदर्शन',
  'common.runScan': 'स्कैन चलाएँ', 'common.open': 'खोलें', 'common.close': 'बंद करें', 'common.download': 'डाउनलोड करें',
  'common.retry': 'फिर से प्रयास करें', 'common.source': 'स्रोत', 'common.cancel': 'रद्द करें', 'common.save': 'सहेजें',
  'common.clearFilters': 'फ़िल्टर हटाएँ', 'common.skip': 'मुख्य सामग्री पर जाएँ', 'common.all': 'सभी',
  'overview.doNext': 'आगे क्या करें', 'overview.milestones': 'DST समय-सीमाएँ', 'overview.systems': 'प्रणाली के अनुसार जोखिम',
  'overview.coverage': 'कवरेज और साक्ष्य', 'fig.inventoried': 'सूचीबद्ध परिसंपत्तियाँ',
  'fig.vulnerable': 'क्वांटम-असुरक्षित', 'fig.exposed': 'माइग्रेशन से पहले उजागर', 'fig.gated': 'आपूर्तिकर्ताओं पर निर्भर',
  'status.broken': 'टूटा हुआ', 'status.vulnerable': 'असुरक्षित', 'status.weakened': 'कमज़ोर', 'status.safe': 'सुरक्षित',
  'status.unresolved': 'अनिर्धारित', 'mosca.certain': 'उजागर', 'mosca.likely': 'संभवतः उजागर',
  'mosca.possible': 'शायद उजागर', 'mosca.clear': 'समय रहते सुरक्षित', 'mosca.not_applicable': 'लागू नहीं',
  'risk.exposure': 'क्वांटम जोखिम', 'risk.drift': 'नीति विचलन', 'risk.dependencies': 'निर्भरताएँ',
  'risk.scores': 'स्कोर विश्लेषण', 'risk.after': 'माइग्रेशन के बाद', 'plan.waves': 'चरण', 'plan.simulate': 'अनुकरण',
  'evidence.compliance': 'अनुपालन', 'settings.api': 'API पहुँच',
  'plan.actions': 'कार्य', 'plan.suppliers': 'आपूर्तिकर्ता', 'plan.timeline': 'समय-रेखा',
  'evidence.reports': 'रिपोर्ट और निर्यात', 'evidence.certin': 'CERT-In अनुरूपता', 'evidence.integrity': 'अखंडता',
  'evidence.changes': 'परिवर्तन', 'evidence.detector': 'डिटेक्टर', 'evidence.method': 'पद्धति',
  'settings.runtime': 'संचालन', 'settings.users': 'उपयोगकर्ता और भूमिकाएँ', 'settings.model': 'सहायक मॉडल',
  'settings.policy': 'प्रोफ़ाइल और नीति', 'settings.access': 'सुलभता और भाषा',
  'panel.summary': 'सारांश', 'panel.evidence': 'साक्ष्य', 'panel.risk': 'क्वांटम जोखिम', 'panel.fix': 'सुधार',
  'panel.dependencies': 'निर्भरताएँ', 'panel.history': 'इतिहास',
  'auth.signIn': 'साइन इन करें', 'auth.username': 'उपयोगकर्ता नाम', 'auth.password': 'पासवर्ड',
  'auth.bootstrap': 'पहला व्यवस्थापक बनाएँ', 'role.admin': 'व्यवस्थापक', 'role.analyst': 'विश्लेषक', 'role.viewer': 'दर्शक',
  'overview.report': 'आकलन रिपोर्ट (PDF)', 'common.scanAgain': 'फिर से स्कैन करें', 'overview.allActions': 'सभी कार्य',
  'ms.met': 'पूरा हुआ', 'ms.in_progress': 'प्रगति पर', 'ms.at_risk': 'जोखिम में', 'ms.missed': 'चूक गया',
  'common.export': 'ये पंक्तियाँ निर्यात करें (CSV)', 'common.search': 'खोजें',
};

const DICTIONARIES = { en: EN, hi: HI };

const PrefsContext = createContext(null);

export function PrefsProvider({ children }) {
  const [prefs, setPrefs] = useState(read);
  const [themeNote, setThemeNote] = useState(null);
  // Track last announced theme (not a boolean boot flag) so React Strict Mode remounts do not flash a pill.
  const lastTheme = useRef(null);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = prefs.theme;
    root.dataset.text = prefs.text;
    root.lang = prefs.lang;
    write(prefs);
  }, [prefs]);

  // Theme change announcement: skip until the user actually changes theme.
  useEffect(() => {
    if (lastTheme.current === null) {
      lastTheme.current = prefs.theme;
      return undefined;
    }
    if (lastTheme.current === prefs.theme) return undefined;
    lastTheme.current = prefs.theme;
    const root = document.documentElement;
    root.classList.add('theme-switching');
    const label = prefs.theme === 'dark' ? 'Dark mode on' : 'Light mode on';
    setThemeNote(label);
    const clearClass = window.setTimeout(() => root.classList.remove('theme-switching'), 400);
    const clearNote = window.setTimeout(() => setThemeNote(null), 1400);
    return () => {
      window.clearTimeout(clearClass);
      window.clearTimeout(clearNote);
      root.classList.remove('theme-switching');
    };
  }, [prefs.theme]);

  const value = useMemo(() => {
    const dictionary = DICTIONARIES[prefs.lang] || EN;
    return {
      prefs,
      set: (changes) => setPrefs((now) => ({ ...now, ...changes })),
      t: (key) => dictionary[key] ?? EN[key] ?? key,
    };
  }, [prefs]);

  return (
    <PrefsContext.Provider value={value}>
      {children}
      {themeNote && (
        <div className="theme-switch-pill" role="status" aria-live="polite">{themeNote}</div>
      )}
    </PrefsContext.Provider>
  );
}

export function usePrefs() {
  return useContext(PrefsContext);
}

export function useT() {
  return useContext(PrefsContext).t;
}
