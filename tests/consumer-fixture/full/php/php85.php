<?php
// SYNTHETIC SECURITY FIXTURE -- INTENTIONALLY VULNERABLE -- DO NOT DEPLOY.
// PHP 8.5: final promoted property and the (void) cast -- Semgrep PartialParsing (PARTIAL)
final class Box {
    public function __construct(final public int $size) {}
}
(void) strlen("ignored");
system("ping -c 1 " . $_GET['host']);
