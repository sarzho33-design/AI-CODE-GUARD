export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  /** Which check produced this: 'secret' | 'dangerous-command' | 'dependency' | 'permission' | 'injection' | 'ai' */
  source: string;
  severity: Severity;
  title: string;
  file: string;
  line?: number;
  evidence: string;      // the actual matched snippet / quoted code — never invented
  explanation: string;   // why this is dangerous
  recommendation: string;
  confidence?: number;   // 0-100, mainly used by the AI check
}

export interface ChangedFile {
  filename: string;
  status: string; // added | modified | removed | renamed
  additions: number;
  deletions: number;
  patch?: string; // unified diff hunk, undefined for binary/too-large files
}

export interface PullRequestDiff {
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  files: ChangedFile[];
}
