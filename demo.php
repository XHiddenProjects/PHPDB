
<?php
require_once __DIR__ . '/phpdb.php';

use XHiddenProjects\PHPDB\PHPDB;
use XHiddenProjects\PHPDB\PHPDBSecurity;
use XHiddenProjects\PHPDB\PHPDBException;

// ------------------------------------------------------------
// 1) (Optional) lock down the /data folder for .phpdb files
// ------------------------------------------------------------
PHPDBSecurity::secureDatabase(__DIR__ . '/data', PHPDBSecurity::EX_LOCK); // creates .htaccess/nginx snippet
// Tip: create the folder if it doesn't exist.
if (!is_dir(__DIR__ . '/data')) {
    mkdir(__DIR__ . '/data', 0750, true);
}

// ------------------------------------------------------------
// 2) Bootstrap credentials file (phpdb.json) ONCE
//    - Creates an 'admin' account that can access all databases
// ------------------------------------------------------------
$credPath = __DIR__ . '/phpdb.json';
if (!is_file($credPath)) {
    PHPDBSecurity::createAccount(
        key:       'admin',                       // account key
        username:  'admin',                       // login username
        password:  'ChangeThisStrongPassword!',   // PLEASE change this
        role:      'admin',
        databases: ['*'],                         // can access any DB
        can_view:  true,
        can_write: true,
        can_create:true,
        can_delete:true,
        credPath:  $credPath
    );
    echo "✅ Created phpdb.json with admin account\n";
}

// Helper to (re)authorize before each create/open (the library requires this)
function auth(PHPDB $db): void {
    $db->Authorize('admin', 'ChangeThisStrongPassword!'); // re-auth when needed
}

// Create one PHPDB instance wired to our cred file
$db = new PHPDB($credPath);

try {
    $dbRoot = __DIR__ . '/data';

    // --------------------------------------------------------
    // 3) Create TWO databases: 'sales' and 'hr'
    //    (v2 encryption uses the authorized password for KDF)
    // --------------------------------------------------------
    // SALES DB
    auth($db);
    $db->createDatabase('sales', $dbRoot);                         // creates sales.phpdb
    auth($db);
    if (!$db->open('sales')) {
        throw new PHPDBException("Failed to open DB: sales");
    }

    // Create tables in 'sales'
    $db->createTable('orders', [
        'id'        => 'INT AUTO_INCREMENT UNIQUE',
        'item'      => 'VARCHAR(100) NOT NULL',
        'quantity'  => 'INT NOT NULL',
        'price'     => 'FLOAT NOT NULL',
        'ordered_at'=> 'DATETIME NOT NULL'
    ]);
    $db->createTable('customers', [
        'id'        => 'INT AUTO_INCREMENT UNIQUE',
        'name'      => 'VARCHAR(80) NOT NULL',
        'email'     => 'VARCHAR(120) UNIQUE NOT NULL',
        // Example: foreign key-like column; library enforces FKs via column definition token "REFERENCES table(col)".
        // (Optional) 'customer_id' => 'INT REFERENCES orders(id) ON DELETE RESTRICT'
    ]);

    // Insert demo rows into 'sales'
    $db->insert('customers', [
        'name'  => 'Acme Corp',
        'email' => 'billing@acme.test'
    ]);
    $db->insert('orders', [
        'item'       => 'Widget',
        'quantity'   => 10,
        'price'      => 9.99,
        'ordered_at' => '2025-12-01 08:30:00'
    ]);

    echo "✅ 'sales' DB ready\n";

    // --------------------------------------------------------
    // 4) Switch to the OTHER database: 'hr'
    // --------------------------------------------------------
    // HR DB
    auth($db);
    $db->createDatabase('hr', $dbRoot);                            // creates hr.phpdb
    if (!$db->open('hr')) {
        throw new PHPDBException("Failed to open DB: hr");
    }

    // Create tables in 'hr'
    $db->createTable('employees', [
        'id'        => 'INT AUTO_INCREMENT UNIQUE',
        'name'      => 'VARCHAR(80) NOT NULL',
        'title'     => 'VARCHAR(80) NOT NULL',
        'salary'    => 'FLOAT NOT NULL',
        'hired_at'  => 'DATETIME NOT NULL'
    ]);
    $db->createTable('departments', [
        'id'        => 'INT AUTO_INCREMENT UNIQUE',
        'name'      => 'VARCHAR(80) UNIQUE NOT NULL'
    ]);

    // Insert demo rows into 'hr'
    $db->insert('departments', [
        'name' => 'Engineering'
    ]);
    $db->insert('employees', [
        'name'     => 'Jane Doe',
        'title'    => 'Senior Engineer',
        'salary'   => 145000.00,
        'hired_at' => '2025-11-15 09:00:00'
    ]);

    echo "✅ 'hr' DB ready\n";

    // --------------------------------------------------------
    // 5) Read examples from EACH DB
    // --------------------------------------------------------

    // Read from HR (current open DB is 'hr')
    $oneEmp = $db->fetch('employees', "WHERE salary >= 140000 ORDER BY hired_at DESC");
    echo "\n📎 HR.fetch(): salary >= 140000 (first match)\n";
    print_r($oneEmp);

    // Close HR
    $db->close('hr');

    // Re-open SALES and read
    auth($db);
    if (!$db->open('sales')) {
        throw new PHPDBException("Failed to re-open DB: sales");
    }

    $ordersToday = $db->fetchAll('orders',
        "WHERE ordered_at >= '2025-12-01 00:00:00' AND ordered_at < '2025-12-02 00:00:00'",
        "ordered_at ASC"
    );
    echo "\n📎 SALES.fetchAll(): orders on 2025-12-01\n";
    print_r($ordersToday);

    // --------------------------------------------------------
    // 6) Clean shutdown
    // --------------------------------------------------------
    $db->close('sales');
    echo "\n✅ Done. Both DBs saved/closed.\n";

} catch (PHPDBException $e) {
    echo "❌ PHPDBException: " . $e->getMessage() . PHP_EOL;
} catch (Throwable $e) {
    echo "❌ Unexpected error: " . $e->getMessage() . PHP_EOL;
}
