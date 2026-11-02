const ICONS = { pass: '✓', warn: '!', fail: '✗', info: '·' };

export function printReport(target, finalUrl, findings, score, grade) {
  const lines = [];
  lines.push('');
  lines.push(`headerpatrol: ${target}`);
  if (finalUrl !== target) lines.push(`final URL:    ${finalUrl}`);
  lines.push('');

  const width = Math.max(...findings.map((f) => f.name.length));
  for (const f of findings) {
    lines.push(`  [${ICONS[f.status]}] ${f.name.padEnd(width)}  ${f.detail}`);
  }

  lines.push('');
  lines.push(`Score: ${score}/100  Grade: ${grade}`);
  lines.push('');
  return lines.join('\n');
}
