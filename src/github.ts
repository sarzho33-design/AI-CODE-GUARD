import * as github from '@actions/github';
import * as core from '@actions/core';
import { minimatch } from 'minimatch';
import { ChangedFile, PullRequestDiff, Finding } from './types';

export async function getPullRequestDiff(
  token: string,
  ignoreGlobs: string[]
): Promise<PullRequestDiff | null> {
  const octokit = github.getOctokit(token);
  const ctx = github.context;

  const pr = ctx.payload.pull_request;
  if (!pr) {
    core.info('Not a pull_request event — nothing to analyze.');
    return null;
  }

  const { owner, repo } = ctx.repo;
  const prNumber = pr.number;

  // Paginate through changed files — don't assume PRs are small.
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    owner,
    repo,
    pull_number: prNumber,
    per_page: 100,
  });

  const changed: ChangedFile[] = files
    .filter((f) => !ignoreGlobs.some((g) => minimatch(f.filename, g)))
    .map((f) => ({
      filename: f.filename,
      status: f.status,
      additions: f.additions,
      deletions: f.deletions,
      patch: f.patch, // GitHub omits `patch` for binary or very large files
    }));

  return {
    owner,
    repo,
    prNumber,
    headSha: pr.head.sha,
    files: changed,
  };
}

export async function postReportComment(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
  body: string
): Promise<void> {
  const octokit = github.getOctokit(token);

  // Find an existing AI Code Guard comment to update instead of spamming new ones.
  const marker = '<!-- ai-code-guard-report -->';
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number: prNumber,
    per_page: 100,
  });
  const existing = comments.find((c) => c.body?.includes(marker));

  const fullBody = `${marker}\n${body}`;

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body: fullBody,
    });
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body: fullBody,
    });
  }
}

export function worstSeverity(findings: Finding[]): Finding['severity'] | 'none' {
  const order: Finding['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const s of order) {
    if (findings.some((f) => f.severity === s)) return s;
  }
  return 'none';
}
