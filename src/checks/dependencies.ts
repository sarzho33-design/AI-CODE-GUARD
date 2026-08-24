import { ChangedFile, Finding } from '../types';
import { addedLines } from './diffUtils';

const MANIFESTS = ['package.json', 'requirements.txt', 'Pipfile', 'go.mod', 'Gemfile', 'Cargo.toml'];

export function checkDependencies(files: ChangedFile[]): Finding[] {
  const findings: Finding[] = [];

  const manifestFiles = files.filter((f) =>
    MANIFESTS.some((m) => f.filename === m || f.filename.endsWith(`/${m}`))
  );

  for (const file of manifestFiles) {
    if (!file.patch) continue;
    const added = addedLines(file.patch);

    for (const { lineNumber, content } of added) {
      // Non-registry source: git URL or local path dependency — bypasses the
      // package registry's (weak but real) abuse detection entirely.
      if (/(git\+https?:\/\/|github:|file:)/i.test(content)) {
        findings.push({
          source: 'dependency',
          severity: 'medium',
          title: 'Dependency installed from a non-registry source',
          file: file.filename,
          line: lineNumber,
          evidence: content.trim().slice(0, 200),
          explanation: 'Git/URL/file dependencies bypass npm/PyPI registry safeguards and can change contents after review without a version bump.',
          recommendation: 'Prefer a pinned registry release. If a fork/URL is required, pin to a specific commit SHA, not a branch.',
          confidence: 55,
        });
      }

      // Wildcard or unbounded version ranges
      if (/"[^"]+"\s*:\s*"[*x]"/i.test(content) || /"[^"]+"\s*:\s*"\s*>=?\s*\d/.test(content)) {
        findings.push({
          source: 'dependency',
          severity: 'low',
          title: 'Dependency version not pinned',
          file: file.filename,
          line: lineNumber,
          evidence: content.trim().slice(0, 200),
          explanation: 'Wildcard or open-ended version ranges let future malicious or broken releases get pulled in automatically (a common supply-chain attack vector).',
          recommendation: 'Pin to an exact version or a narrow caret/tilde range, and rely on a lockfile.',
          confidence: 50,
        });
      }
    }
  }

  // NOTE: this deterministic pass intentionally does NOT call out to a live
  // vulnerability database (e.g. OSV, npm audit) yet — that's a good Phase 2
  // follow-up (`osv-scanner` or `npm audit --json` as a subprocess step).
  return findings;
}
