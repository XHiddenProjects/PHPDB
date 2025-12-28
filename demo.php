
<?php
require_once __DIR__ . '/phpdb.php';

use XHiddenProjects\PHPDB\PHPDB;
use XHiddenProjects\PHPDB\PHPDBSecurity;
use XHiddenProjects\PHPDB\PHPDBException;

// Optional: lock down /data folder for .phpdb files
PHPDBSecurity::secureDatabase(__DIR__ . '/data', PHPDBSecurity::EX_LOCK);

$credPath = __DIR__ . '/phpdb.json';

// Create credentials once (only if missing)
if (!is_file($credPath)) {
    PHPDBSecurity::createAccount(
        key: 'admin',
        username: 'admin',
        password: 'ChangeThisStrongPassword!',
        role: 'admin',
        databases: ['*'],
        can_view: true,
        can_write: true,
        can_create: true,
        can_delete: true,
        credPath: $credPath
    );
    echo "✅ Created phpdb.json with admin account\n";
}

$db = new PHPDB($credPath);

try {
    // Authorize
    $db->Authorize('admin', 'ChangeThisStrongPassword!');

    // Create & Open DB
    $dbName = 'myapp';
    $dbPath = __DIR__ . '/data';
    $db->createDatabase($dbName, $dbPath);

    if (!$db->open($dbName)) {
        throw new PHPDBException("Failed to open DB: $dbName");
    }

    // Create table with INT, FLOAT, DATETIME, STRING
    $db->createTable('users', [
        'id'       => 'INT AUTO_INCREMENT UNIQUE',
        'username' => 'VARCHAR(50) UNIQUE NOT NULL',
        'age'      => 'INT NOT NULL',
        'score'    => 'FLOAT NOT NULL',
        'created'  => 'DATETIME NOT NULL'
    ]);

    echo "✅ DB open and table ready\n";

    // Insert demo rows (with different ages, scores, created dates)
    $db->insert('users', [
        'username' => 'demo',
        'age'      => 3,
        'score'    => 10.25,
        'created'  => '2025-12-01 08:30:00'
    ]);

    $db->insert('users', [
        'username' => 'alex',
        'age'      => 7,
        'score'    => 99.50,
        'created'  => '2025-12-01 12:00:00'
    ]);

    $db->insert('users', [
        'username' => 'sam',
        'age'      => 15,
        'score'    => 50.10,
        'created'  => '2025-12-02 09:15:00'
    ]);

    echo "✅ Inserted demo users\n";

    // -------------------------
    // ✅ FETCH ONE (first match)
    // -------------------------

    // 1) Number condition (age > 5)
    $oneAge = $db->fetch('users', "WHERE age > 5 ORDER BY age ASC");
    echo "\n📌 fetch(): age > 5 (first match)\n";
    print_r($oneAge);

    // 2) Float condition (score >= 50.0)
    $oneScore = $db->fetch('users', "WHERE score >= 50.0 ORDER BY score DESC");
    echo "\n📌 fetch(): score >= 50.0 (first match)\n";
    print_r($oneScore);

    // 3) String condition (username == 'alex')
    $oneName = $db->fetch('users', "WHERE username == 'alex'");
    echo "\n📌 fetch(): username == 'alex'\n";
    print_r($oneName);

    // 4) Datetime condition (created on 2025-12-01)
    $oneDate = $db->fetch(
        'users',
        "WHERE created >= '2025-12-01 00:00:00' AND created < '2025-12-02 00:00:00' ORDER BY created ASC"
    );
    echo "\n📌 fetch(): created on 2025-12-01 (first match)\n";
    print_r($oneDate);

    // -------------------------
    // ✅ FETCH ALL (all matches)
    // -------------------------

    // All rows created on 2025-12-01
    $allOnDay = $db->fetchAll(
        'users',
        "WHERE created >= '2025-12-01 00:00:00' AND created < '2025-12-02 00:00:00'",
        "created ASC"
    );

    echo "\n📌 fetchAll(): created on 2025-12-01 (ALL matches)\n";
    print_r($allOnDay);

    // All rows age > 5 and score > 50
    $allCombo = $db->fetchAll(
        'users',
        "WHERE age > 5 AND score > 50",
        "score DESC"
    );

    echo "\n📌 fetchAll(): age > 5 AND score > 50 (ALL matches)\n";
    print_r($allCombo);

    // Close DB
    $db->close($dbName);
    echo "\n✅ Done. DB saved/closed.\n";

} catch (PHPDBException $e) {
    echo "❌ PHPDBException: " . $e->getMessage() . PHP_EOL;
} catch (Throwable $e) {
    echo "❌ Unexpected error: " . $e->getMessage() . PHP_EOL;
}
