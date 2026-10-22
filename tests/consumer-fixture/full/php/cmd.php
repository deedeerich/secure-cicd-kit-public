<?php
// SYNTHETIC SECURITY FIXTURE -- INTENTIONALLY VULNERABLE -- DO NOT DEPLOY.
// semgrep p/php tainted-exec: request input in a shell command
system("ping -c 1 " . $_GET['host']);
