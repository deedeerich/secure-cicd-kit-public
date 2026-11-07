<?php
// SYNTHETIC SECURITY FIXTURE -- INTENTIONALLY VULNERABLE -- DO NOT DEPLOY.
// semgrep p/php tainted-sql-string: request input concatenated into SQL
$id = $_GET['id'];
$conn = mysqli_connect('localhost', 'u', 'p', 'db');
$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
