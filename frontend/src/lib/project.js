/* The project you are working in: the assistant files its conversations under it and the top bar shows it.
 * Kept in this browser only (like display preferences); storage may be unavailable, so every access tolerates that. */
import { useEffect, useState } from 'react';

const KEY = 'vera.project';
const EVENT = 'vera:project';

export function currentProject() {
  try {
    return JSON.parse(window.localStorage.getItem(KEY) || 'null');
  } catch {
    return null;
  }
}

export function setCurrentProject(project) {
  try {
    if (project) window.localStorage.setItem(KEY, JSON.stringify({ id: project.id, name: project.name }));
    else window.localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the choice lasts for this visit only */
  }
  window.dispatchEvent(new CustomEvent(EVENT, { detail: project }));
}

export function useCurrentProject() {
  const [project, setProject] = useState(currentProject);
  useEffect(() => {
    const on = () => setProject(currentProject());
    window.addEventListener(EVENT, on);
    window.addEventListener('storage', on);
    return () => {
      window.removeEventListener(EVENT, on);
      window.removeEventListener('storage', on);
    };
  }, []);
  return project;
}
