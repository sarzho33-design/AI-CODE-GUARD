import { ChangedFile, Finding } from '../types';
import { addedLines } from './diffUtils';

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Finding['severity'];
}

// Only match added lines — we care about NEW secrets introduced by this PR,
// not pre-existing ones (those are a separate historical-scan problem).
const PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/, severity: 'critical' },
  { name: 'AWS Secret Access Key (heuristic)', regex: /aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/i, severity: 'critical' },
  { name: 'GitHub Personal Access Token', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, severity: 'critical' },
  { name: 'Generic private key block', regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, severity: 'critical' },
  { name: 'Slack token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: 'critical' },
  { name: 'Stripe API key', regex: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}\b/, severity: 'critical' },
  { name: 'Google API key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, severity: 'high' },
  { name: 'Anthropic API key', regex: /\bsk-ant-[0-9A-Za-z\-_]{20,}\b/, severity: 'critical' },
  { name: 'OpenAI API key', regex: /\bsk-[A-Za-z0-9]{20,}\b/, severity: 'high' },
  { name: 'Generic hardcoded password assignment', regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{6,}['"]/i, severity: 'medium' },
  { name: 'Generic hardcoded secret/token assignment', regex: /(secret|token|api[_-]?key)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/i, severity: 'medium' },
  { name: 'JWT literal', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium' },
];

// Common false-positive suppressors: placeholders, examples, env var references.
const PLACEHOLDER_HINTS = /(example|placeholder|dummy|fake|xxxx+|<.*>|\$\{|process\.env|your[-_]?api[-_]?key|changeme)/i;

export function checkSecrets(files: ChangedFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.patch) continue;
    for (const { lineNumber, content } of addedLines(file.patch)) {
      for (const pattern of PATTERNS) {
        const match = content.match(pattern.regex);
        if (!match) continue;
        if (PLACEHOLDER_HINTS.test(content)) continue; // reduce false positives

        findings.push({
          source: 'secret',
          severity: pattern.severity,
          title: `Possible hardcoded ${pattern.name}`,
          file: file.filename,
          line: lineNumber,
          evidence: content.trim().slice(0, 200),
          explanation: `This line matches the pattern for a ${pattern.name}. Committing real credentials exposes them to anyone with repo access and to the full git history, even if removed later.`,
          recommendation: 'Remove the credential from source, rotate it immediately if it was ever real, and load it from a secrets manager or environment variable instead.',
          confidence: 85,
        });
      }
    }
  }

  return findings;
}
