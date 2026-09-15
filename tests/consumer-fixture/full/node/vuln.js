const cp = require('child_process');
function run(userInput) {
  // semgrep: command injection
  return cp.execSync('ls ' + userInput);
}
function evalIt(s) { return eval(s); }   // semgrep: eval
module.exports = { run, evalIt };
