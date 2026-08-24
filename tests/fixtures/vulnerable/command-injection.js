// Intentionally vulnerable fixture — used to verify checkDangerousCommands() catches it.
const { execSync } = require('child_process');

function resizeImage(filename) {
  // filename comes from user upload — never sanitized before hitting the shell
  return execSync(`convert ${filename} -resize 50% output.png`);
}

module.exports = { resizeImage };
