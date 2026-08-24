import { Finding } from './types';

const SEVERITY_EMOJI: Record<Finding['severity'], string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: 'ℹ️',
};

const RISK_LABEL: Record<Finding['severity'] | 'none', string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
  none: 'NONE',
};

export function formatReport(
  findings: Finding[],
  overallRisk: Finding['severity'] | 'none',
  checksRun: number
): string {
  const critical = findings.filter((f) => f.severity === 'critical');
  const high = findings.filter((f) => f.severity === 'high');
  const medium = findings.filter((f) => f.severity === 'medium');
  const lowOrInfo = findings.filter((f) => f.severity === 'low' || f.severity === 'info');
  const passed = checksRun - findings.length > 0 ? checksRun - findings.length : 0;

  const lines: string[] = [];
  lines.push(`## 🛡️ AI Code Guard`);
  lines.push('');
  lines.push(`**Risk: ${RISK_LABEL[overallRisk]}**`);
  lines.push('');
  lines.push(
    [
      critical.length ? `${SEVERITY_EMOJI.critical} ${critical.length} critical` : null,
      high.length ? `${SEVERITY_EMOJI.high} ${high.length} high` : null,
      medium.length ? `${SEVERITY_EMOJI.medium} ${medium.length} medium` : null,
      lowOrInfo.length ? `${SEVERITY_EMOJI.low} ${lowOrInfo.length} low/info` : null,
      `🟢 ${passed} checks passed`,
    ]
      .filter(Boolean)
      .join(' &nbsp;|&nbsp; ')
  );
  lines.push('');

  const bySeverity = [...critical, ...high, ...medium, ...lowOrInfo];

  if (bySeverity.length === 0) {
    lines.push('No issues found in the changed code. ✅');
  }

  for (const f of bySeverity) {
    lines.push('---');
    lines.push(`### ${SEVERITY_EMOJI[f.severity]} ${f.title}`);
    lines.push(`**File:** \`${f.file}${f.line ? `:${f.line}` : ''}\`${f.confidence !== undefined ? `  \n**Confidence:** ${f.confidence}%` : ''}`);
    lines.push('');
    lines.push('**Evidence:**');
    lines.push('```');
    lines.push(f.evidence);
    lines.push('```');
    lines.push('');
    lines.push(`**Why this matters:** ${f.explanation}`);
    lines.push('');
    lines.push(`**Suggested fix:** ${f.recommendation}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('_AI Code Guard checks changed code only. Deterministic checks (secrets, dangerous commands, permissions, dependencies, injection patterns) run first; AI review adds context-aware analysis on top, and only reports findings backed by a real snippet from the diff._');

  return lines.join('\n');
}
