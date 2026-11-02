import { WEIGHTS } from './checks.js';

// Start at 100, knock points off for every real problem.
// 'info' findings are observations, they never cost points.
export function scoreFindings(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.status === 'fail') score -= WEIGHTS.fail;
    else if (f.status === 'warn') score -= WEIGHTS.warn;
  }
  return Math.max(0, score);
}

export function gradeFor(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
