import type { StoredUser } from "./storage";

// Trial helpers shared by the route guard (hard stop on expiry) and the
// app chrome (countdown badge). A user is "on a trial" only when the
// backend marked plan === "trial" and gave a trial_ends_at timestamp;
// every other account (admin, unlimited self-host) is unaffected.

type TrialFields = Pick<StoredUser, "plan" | "trial_ends_at">;

const DAY_MS = 86_400_000;

/** Whole days remaining on a trial, or null when the user isn't on one. */
export function trialDaysLeft(user: TrialFields): number | null {
  if (user.plan !== "trial" || !user.trial_ends_at) return null;
  const ms = new Date(user.trial_ends_at).getTime() - Date.now();
  if (Number.isNaN(ms)) return null;
  return Math.max(0, Math.ceil(ms / DAY_MS));
}

/** True only for a trial account whose window has already elapsed. */
export function isTrialExpired(user: TrialFields): boolean {
  if (user.plan !== "trial" || !user.trial_ends_at) return false;
  const end = new Date(user.trial_ends_at).getTime();
  return !Number.isNaN(end) && end <= Date.now();
}
