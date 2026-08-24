import { ChangedFile, Finding } from '../types';
import { addedLines } from './diffUtils';

interface InjectionPattern {
  name: string;
  regex: RegExp;
  severity: Finding['severity'];
  explanation: string;
}

// These are intentionally narrow / high-signal. Broad "any string concat near SQL"
// patterns produce too many false positives — save the fuzzy judgment calls for
// the AI review step, which can look at more context.
const PATTERNS: InjectionPattern[] = [
  {
    name: 'SQL query built via string concatenation/template with a variable',
    regex: /(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,200}?[`'"]\s*\+\s*\w+|(SELECT|INSERT|UPDATE|DELETE)\b.*\$\{[^}]+\}/i,
    severity: 'high',
    explanation: 'Building SQL by concatenating or interpolating variables directly into the query string allows SQL injection if any part is user-controlled.',
  },
  {
    name: 'innerHTML / dangerouslySetInnerHTML assigned from a variable',
    regex: /(innerHTML\s*=\s*\w|dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*\w)/,
    severity: 'medium',
    explanation: 'Rendering unsanitized content as raw HTML can allow stored or reflected XSS if the value ever originates from user input.',
  },
  {
    name: 'os/exec command built from concatenated input',
    regex: /os\.system\(\s*[^)]*\+|exec\.Command\([^)]*\+\s*\w/,
    severity: 'high',
    explanation: 'Concatenating variables into a system command string risks command injection.',
  },
];

export function checkInjection(files: ChangedFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.patch) continue;
    for (const { lineNumber, content } of addedLines(file.patch)) {
      for (const pattern of PATTERNS) {
        if (!pattern.regex.test(content)) continue;
        findings.push({
          source: 'injection',
          severity: pattern.severity,
          title: pattern.name.charAt(0).toUpperCase() + pattern.name.slice(1),
          file: file.filename,
          line: lineNumber,
          evidence: content.trim().slice(0, 200),
          explanation: pattern.explanation,
          recommendation: 'Use parameterized queries / prepared statements, framework-provided sanitization, or an allowlist instead of raw string building.',
          confidence: 60, // deliberately lower — these patterns are heuristic and benefit from AI confirmation
        });
      }
    }
  }

  return findings;
}
