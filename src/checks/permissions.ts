import { ChangedFile, Finding } from '../types';
import { addedLines } from './diffUtils';

export function checkPermissions(files: ChangedFile[]): Finding[] {
  const findings: Finding[] = [];

  const workflowFiles = files.filter((f) => /^\.github\/workflows\/.*\.ya?ml$/.test(f.filename));

  for (const file of workflowFiles) {
    if (!file.patch) continue;
    const lines = addedLines(file.patch);
    const joined = lines.map((l) => l.content).join('\n');

    if (/permissions\s*:\s*write-all/.test(joined)) {
      const hit = lines.find((l) => /write-all/.test(l.content));
      findings.push({
        source: 'permission',
        severity: 'high',
        title: 'Workflow grants write-all permissions',
        file: file.filename,
        line: hit?.lineNumber,
        evidence: hit?.content.trim().slice(0, 200) ?? 'permissions: write-all',
        explanation: 'write-all grants the workflow token full read/write access to the repository (contents, packages, deployments, etc.), far more than most jobs need.',
        recommendation: 'Scope permissions to the minimum required, e.g. `contents: read` plus only the specific write scopes the job uses.',
        confidence: 90,
      });
    }

    if (/pull_request_target/.test(joined) && /\bcheckout@/.test(joined) && /ref\s*:\s*.*head/.test(joined)) {
      findings.push({
        source: 'permission',
        severity: 'critical',
        title: 'pull_request_target checks out PR head with elevated token',
        file: file.filename,
        evidence: 'pull_request_target trigger + checkout of PR head ref',
        explanation: 'pull_request_target runs with the base repo\'s secrets and write token, but this pattern checks out the untrusted PR head — letting a malicious PR run its own code with your repo\'s privileges.',
        recommendation: 'Avoid checking out untrusted head refs under pull_request_target. Use pull_request (no secrets) for untrusted code, or explicitly restrict what the elevated job can do.',
        confidence: 80,
      });
    }

    if (/self-hosted/.test(joined) && /\bpull_request\b/.test(joined) && !/pull_request_target/.test(joined)) {
      findings.push({
        source: 'permission',
        severity: 'medium',
        title: 'Self-hosted runner triggered by pull_request',
        file: file.filename,
        evidence: 'runs-on: self-hosted with pull_request trigger',
        explanation: 'Public repos with self-hosted runners on pull_request can let external contributors execute code on your infrastructure via a PR.',
        recommendation: 'Restrict self-hosted runners to trusted triggers (push, workflow_dispatch) or require approval for first-time contributors.',
        confidence: 65,
      });
    }
  }

  return findings;
}
