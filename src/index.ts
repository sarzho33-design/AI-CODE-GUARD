import * as core from '@actions/core';
import { getPullRequestDiff, postReportComment, worstSeverity } from './github';
import { checkSecrets } from './checks/secrets';
import { checkDangerousCommands } from './checks/dangerousCommands';
import { checkPermissions } from './checks/permissions';
import { checkInjection } from './checks/injection';
import { checkDependencies } from './checks/dependencies';
import { runAiReview } from './checks/aiReview';
import { formatReport } from './report';
import { Finding } from './types';

const SEVERITY_RANK: Record<Finding['severity'] | 'none', number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

async function run(): Promise<void> {
  try {
    const token = core.getInput('github-token', { required: true });
    const apiKey = core.getInput('anthropic-api-key');
    const failOn = (core.getInput('fail-on') || 'critical') as Finding['severity'] | 'none';
    const maxFiles = parseInt(core.getInput('max-files') || '30', 10);
    const ignoreGlobs = (core.getInput('ignore-paths') || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    const diff = await getPullRequestDiff(token, ignoreGlobs);
    if (!diff) {
      core.info('No PR diff to analyze - exiting cleanly.');
      return;
    }

    core.info(`Analyzing ${diff.files.length} changed file(s) in PR #${diff.prNumber}`);

    const deterministicFindings: Finding[] = [
      ...checkSecrets(diff.files),
      ...checkDangerousCommands(diff.files),
      ...checkPermissions(diff.files),
      ...checkInjection(diff.files),
      ...checkDependencies(diff.files),
    ];
    const deterministicChecksRun = 5 * diff.files.length;

    let aiFindings: Finding[] = [];
    if (apiKey) {
      try {
        aiFindings = await runAiReview(apiKey, diff.files, maxFiles);
      } catch (err) {
        core.warning(`AI review failed, continuing with deterministic results only: ${(err as Error).message}`);
      }
    } else {
      core.info('No anthropic-api-key provided - skipping AI review, deterministic checks only.');
    }

    const allFindings = [...deterministicFindings, ...aiFindings];
    const risk = worstSeverity(allFindings);

    const proLicenseKey = core.getInput('pro-license-key');
    if (proLicenseKey) {
      try {
        await fetch('https://ai-code-guard-license.sarzho33.workers.dev/log-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            licenseKey: proLicenseKey,
            repo: `${diff.owner}/${diff.repo}`,
            risk,
            findingsCount: allFindings.length,
            prNumber: diff.prNumber,
          }),
        });
      } catch (err) {
        core.warning(`Failed to log scan to history: ${(err as Error).message}`);
      }
    }

    const report = formatReport(allFindings, risk, deterministicChecksRun + (apiKey ? maxFiles : 0));
    await postReportComment(token, diff.owner, diff.repo, diff.prNumber, report);

    core.setOutput('risk-level', risk);
    core.setOutput('findings-json', JSON.stringify(allFindings));

    if (SEVERITY_RANK[risk] >= SEVERITY_RANK[failOn] && failOn !== 'none') {
      core.setFailed(`AI Code Guard found ${risk} severity issue(s). See PR comment for details.`);
    }
  } catch (error) {
    core.setFailed(`AI Code Guard failed to run: ${(error as Error).message}`);
  }
}

run();
