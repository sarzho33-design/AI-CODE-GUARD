import { ChangedFile, Finding } from '../types';
import { addedLines } from './diffUtils';

interface CmdPattern {
  name: string;
  regex: RegExp;
  severity: Finding['severity'];
  explanation: string;
}

const PATTERNS: CmdPattern[] = [
  {
    name: 'curl/wget piped directly into a shell',
    regex: /(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/,
    severity: 'critical',
    explanation: 'Downloads and executes remote code with no integrity check. If the remote source is compromised or the URL is hijacked, this runs arbitrary code.',
  },
  {
    name: 'recursive force delete',
    regex: /rm\s+-rf\s+(\/|\$\{?HOME|~)/,
    severity: 'critical',
    explanation: 'Recursively deletes files from a root or home path with no confirmation — a common pattern in destructive or malicious scripts.',
  },
  {
    name: 'eval() on dynamic input',
    regex: /\beval\s*\(/,
    severity: 'high',
    explanation: 'eval() executes arbitrary strings as code. If any part of the input is influenced by user data, this is a code-injection vector.',
  },
  {
    name: 'shell=True in subprocess (Python)',
    regex: /subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True/,
    severity: 'high',
    explanation: 'shell=True passes the command through a shell, so unsanitized input can inject additional commands.',
  },
  {
    name: 'exec/execSync called with a template literal containing a variable (Node)',
    regex: /\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*`[^`]*\$\{/,
    severity: 'high',
    explanation: 'Building a shell command string from variables and passing it to exec()/execSync() risks command injection if any part of that string is attacker-influenced.',
  },
  {
    name: 'exec/execSync called with a concatenated string (Node)',
    regex: /\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:[`'"][^`'"]*[`'"]\s*\+\s*\w+|\w+\s*\+\s*[`'"])/,
    severity: 'high',
    explanation: 'Building a shell command string from variables and passing it to exec()/execSync() risks command injection if any part of that string is attacker-influenced.',
  },
  {
    name: 'disabled TLS/certificate verification',
    regex: /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|rejectUnauthorized\s*:\s*false)/,
    severity: 'high',
    explanation: 'Disabling certificate verification allows man-in-the-middle attacks on any network request this code makes.',
  },
  {
    name: 'unsafe deserialization',
    regex: /(pickle\.loads?\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads?\()/,
    severity: 'high',
    explanation: 'Deserializing untrusted data with these functions can lead to arbitrary code execution.',
  },
];

export function checkDangerousCommands(files: ChangedFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.patch) continue;
    for (const { lineNumber, content } of addedLines(file.patch)) {
      for (const pattern of PATTERNS) {
        if (!pattern.regex.test(content)) continue;
        findings.push({
          source: 'dangerous-command',
          severity: pattern.severity,
          title: pattern.name.charAt(0).toUpperCase() + pattern.name.slice(1),
          file: file.filename,
          line: lineNumber,
          evidence: content.trim().slice(0, 200),
          explanation: pattern.explanation,
          recommendation: 'Review whether this is necessary; if so, add strict input validation/allowlisting and avoid shell interpolation of untrusted data.',
          confidence: 75,
        });
      }
    }
  }

  return findings;
}
