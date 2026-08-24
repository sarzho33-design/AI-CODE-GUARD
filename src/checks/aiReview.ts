import Anthropic from '@anthropic-ai/sdk';
import { ChangedFile, Finding } from '../types';

const SYSTEM_PROMPT = `You are a security reviewer examining a GitHub pull request diff for vulnerabilities.

Rules you MUST follow:
1. Only report a finding if you can point to a specific line of ADDED code (lines starting with "+" in the diff) as evidence. Never report a finding based on removed or unchanged context lines.
2. Never invent or paraphrase evidence — the "evidence" field must be an exact substring of the diff you were given.
3. If you are not confident something is exploitable, either omit it or report it at low severity with a confidence score under 50.
4. Do not repeat issues already likely caught by simple pattern matching (hardcoded secrets, obvious eval() calls) unless you have additional context that changes the risk assessment.
5. Focus on logic-level and context-dependent issues that require understanding intent: broken auth/authorization checks, missing input validation on a path that reaches a sink, business-logic flaws, race conditions, insecure defaults.
6. If the diff shows nothing concerning, return an empty findings array. Do not manufacture findings to seem thorough.`;

const FINDINGS_TOOL = {
  name: 'report_findings',
  description: 'Report security findings from the reviewed diff. Return an empty array if nothing concerning was found.',
  input_schema: {
    type: 'object' as const,
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            title: { type: 'string', description: 'Short finding title' },
            file: { type: 'string' },
            line: { type: 'number', description: 'Best-guess line number in the new file, if determinable' },
            evidence: { type: 'string', description: 'Exact snippet from the diff supporting this finding — must be a real substring of the provided diff' },
            explanation: { type: 'string', description: 'Why this is dangerous' },
            recommendation: { type: 'string', description: 'Concrete suggested fix' },
            confidence: { type: 'number', description: '0-100' },
          },
          required: ['severity', 'title', 'file', 'evidence', 'explanation', 'recommendation', 'confidence'],
        },
      },
    },
    required: ['findings'],
  },
};

export async function runAiReview(
  apiKey: string,
  files: ChangedFile[],
  maxFiles: number
): Promise<Finding[]> {
  const filesWithPatches = files.filter((f) => f.patch).slice(0, maxFiles);
  if (filesWithPatches.length === 0) return [];

  const client = new Anthropic({ apiKey });

  const diffBlock = filesWithPatches
    .map((f) => `--- FILE: ${f.filename} ---\n${f.patch}`)
    .join('\n\n');

  const message = await client.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 4000,
    system: SYSTEM_PROMPT,
    tools: [FINDINGS_TOOL],
    tool_choice: { type: 'tool', name: 'report_findings' },
    messages: [
      {
        role: 'user',
        content: `Review this pull request diff for security issues:\n\n${diffBlock}`,
      },
    ],
  });

  const toolUse = message.content.find(
    (block): block is Anthropic.ToolUseBlock => block.type === 'tool_use'
  );
  if (!toolUse) return [];

  const raw = (toolUse.input as { findings?: unknown[] }).findings ?? [];

  const findings: Finding[] = [];
  for (const item of raw) {
    const f = item as Record<string, unknown>;
    if (
      typeof f.evidence !== 'string' ||
      typeof f.file !== 'string' ||
      typeof f.title !== 'string' ||
      typeof f.explanation !== 'string' ||
      typeof f.recommendation !== 'string'
    ) {
      continue; // drop malformed entries rather than guess
    }

    // Evidence provenance check: reject findings whose "evidence" wasn't
    // actually present in the diff we sent. This is the enforcement of
    // "no evidence = don't report it."
    if (!diffBlock.includes(f.evidence)) {
      continue;
    }

    findings.push({
      source: 'ai',
      severity: (f.severity as Finding['severity']) ?? 'low',
      title: f.title,
      file: f.file,
      line: typeof f.line === 'number' ? f.line : undefined,
      evidence: f.evidence,
      explanation: f.explanation,
      recommendation: f.recommendation,
      confidence: typeof f.confidence === 'number' ? f.confidence : undefined,
    });
  }

  return findings;
}
