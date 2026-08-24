export interface AddedLine {
  lineNumber: number; // line number in the NEW file
  content: string;
}

/**
 * Parses a unified diff patch (as returned by GitHub's pulls.listFiles) and
 * yields only the added lines, with their line number in the resulting file.
 * This is what lets findings point at a real file:line instead of a guess.
 */
export function addedLines(patch: string): AddedLine[] {
  const lines = patch.split('\n');
  const result: AddedLine[] = [];
  let newLineNum = 0;

  const hunkHeader = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

  for (const line of lines) {
    const hunkMatch = line.match(hunkHeader);
    if (hunkMatch) {
      newLineNum = parseInt(hunkMatch[1], 10);
      continue;
    }
    if (line.startsWith('+') && !line.startsWith('+++')) {
      result.push({ lineNumber: newLineNum, content: line.slice(1) });
      newLineNum++;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      // removed line — doesn't consume a new-file line number
      continue;
    } else if (!line.startsWith('\\')) {
      // context line — present in both old and new
      newLineNum++;
    }
  }

  return result;
}
