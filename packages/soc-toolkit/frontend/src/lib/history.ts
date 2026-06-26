// Lightweight, browser-local analysis history (no backend): the last N
// analyses, recorded wherever XP is awarded, shown as "Recent activity" on
// the Dashboard so an analyst can see + jump back to recent work.

const KEY = "soc-toolkit.history.v1";
const MAX = 20;

export type HistoryEntry = {
  action: string; // matches the XP action + the module path slug
  findings: number;
  at: number; // epoch ms
};

export function getHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export function recordAnalysis(action: string, findings: number): void {
  try {
    const next: HistoryEntry[] = [
      { action, findings, at: Date.now() },
      ...getHistory(),
    ].slice(0, MAX);
    localStorage.setItem(KEY, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent("sectk:history-updated"));
  } catch {
    // localStorage unavailable; history is best-effort
  }
}
