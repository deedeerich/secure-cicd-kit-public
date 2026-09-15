const cp = require('child_process');
// semgrep: command injection in a SECOND node root
module.exports = (u) => cp.execSync('cat ' + u);
