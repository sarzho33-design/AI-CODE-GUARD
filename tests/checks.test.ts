import * as fs from 'fs';
import * as path from 'path';
import { checkSecrets } from '../src/checks/secrets';
import { checkDangerousCommands } from '../src/checks/dangerousCommands';
import { checkInjection } from '../src/checks/injection';
import { ChangedFile } from '../src/types';

/**
 * Turns a full fixture file into a synthetic "patch" where every line is
 * an added line, mimicking a brand-new file in a PR. Good enough for
 * exercising the regex checks without needing a real PR diff.
 */
function fixtureAsPatch(filename: string): ChangedFile {
  const fullPath = path.join(__dirname, 'fixtures', filename);
  const content = fs.readFileSync(fullPath, 'utf-8');
  const lines = content.split('\n');
  const patch = [`@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join('\n');
  return { filename, status: 'added', additions: lines.length, deletions: 0, patch };
}

describe('vulnerable fixtures are caught', () => {
  it('detects hardcoded secrets', () => {
    const file = fixtureAsPatch('vulnerable/hardcoded-secret.js');
    const findings = checkSecrets([file]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects SQL injection via concatenation', () => {
    const file = fixtureAsPatch('vulnerable/sql-injection.js');
    const findings = checkInjection([file]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects command injection via execSync template', () => {
    const file = fixtureAsPatch('vulnerable/command-injection.js');
    const findings = checkDangerousCommands([file]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('safe fixtures produce no false positives', () => {
  it('parameterized query triggers nothing', () => {
    const file = fixtureAsPatch('safe/parameterized-query.js');
    expect(checkInjection([file])).toHaveLength(0);
  });

  it('env-based config and placeholder examples trigger nothing', () => {
    const file = fixtureAsPatch('safe/env-config.js');
    expect(checkSecrets([file])).toHaveLength(0);
  });

  it('safe subprocess usage (list args, no shell=True) triggers nothing', () => {
    const file = fixtureAsPatch('safe/safe-subprocess.py');
    expect(checkDangerousCommands([file])).toHaveLength(0);
  });
});
