<?php
// SYNTHETIC SECURITY FIXTURE -- INTENTIONALLY VULNERABLE -- DO NOT DEPLOY.
// semgrep p/php echoed-request: request input echoed unescaped
echo "Hello " . $_GET['name'];
