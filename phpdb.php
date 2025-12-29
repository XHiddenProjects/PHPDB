<?php
namespace XHiddenProjects\PHPDB;
class PHPDB{
    protected array $databases = [];
    protected string $passwordPlain = '';
    protected string $openDB = '';
    protected string $encryptionType = 'AES-256-CBC';
    protected ?string $credPath = null;
    protected array $credConfig = [];
    protected ?array $activeAccount = null;
    protected ?string $activeAccountKey = null;
    protected bool $authorized = false;
    protected ?string $authUsername = null;
    protected ?string $authPassword = null;
    protected ?array $authorizedPayload = null;
    protected ?string $authorizedDbKey = null;
    public const EXPORT_JSON = 'json';
    public const EXPORT_CSV = 'csv';
    public const EXPORT_SQL = 'sql';
    public const EXPORT_SQLite ='sqlite';
    
    
    /**
     * Creates a PHPDB object.
     *
     * NEW (config-driven): credentials are no longer passed into the constructor.
     * Instead, Authorize() loads accounts/roles/db-access from a .json JSON file.
     *
     * @param ?string $credPath Path to phpdb.json (JSON)
     */
    public function __construct(?string $credPath = null) {
        if(file_exists(__DIR__.DIRECTORY_SEPARATOR.'phpdb_pepper.secret'))
            putenv("PHPDB_PEPPER=".file_get_contents(__DIR__.DIRECTORY_SEPARATOR."phpdb_pepper.secret"));
        else{
            if (!getenv('PHPDB_PEPPER')){
                $secret = bin2hex(random_bytes(64));
                putenv("PHPDB_PEPPER=$secret");
                @file_put_contents('phpdb_pepper.secret', $secret);
            }
        }

        
        $this->databases = [];
        $this->openDB = '';
        $this->credPath = $credPath ?? (__DIR__ . DIRECTORY_SEPARATOR . 'phpdb.json');

        PHPDBSecurity::preventDirectAccess();
    }

    /**
     * Authorize the users account
     * @param string $usernameOrAccountKey Username/Account key
     * @param string $password Password
     * @param array{max_attempts: int,windows_seconds: int,lock_seconds: int} $lockoutSettings Lockout settings
     * @return PHPDB
     */
    public function Authorize(string $usernameOrAccountKey, string $password, ?array $lockoutSettings=[]): self{
    // Reset any previous authorization state
    $this->authorized = false;
    $this->authUsername = null;
    $this->authPassword = null;
    $this->authorizedPayload = null;
    $this->authorizedDbKey = null;

    try {
        // Load phpdb.json config and resolve account (by key or username)
        $this->credConfig = $this->loadCredConfig($this->credPath);
        $this->activeAccount = $this->resolveAccount($this->credConfig, $usernameOrAccountKey);
        $this->activeAccountKey = $this->activeAccount['_key'] ?? null;
        // Check lockout (best-effort throttling)
        $u = (string)($this->activeAccount['username'] ?? ($this->activeAccountKey ?? 'unknown'));
        if (PHPDBSecurity::isLockedOut($u, $lockoutSettings['max_attempts']??5, $lockoutSettings['windows_seconds']??300, $lockoutSettings['lock_seconds']??900)) {
            PHPDBSecurity::auditLog("Authorize blocked (locked out): account={$this->activeAccountKey}");
            return $this;
        }
        // Allow config to override cipher
        if (isset($this->credConfig['encryption']) && \is_string($this->credConfig['encryption']) && $this->credConfig['encryption'] !== '') {
            $this->encryptionType = $this->credConfig['encryption'];
        }

        // Verify password against phpdb.json (supports optional env+pepper)
        if (!$this->verifyAccountPassword($this->activeAccount, $password)) {
            $u = (string)($this->activeAccount['username'] ?? ($this->activeAccountKey ?? 'unknown'));
            PHPDBSecurity::recordFailedLogin($u);
            PHPDBSecurity::auditLog("Authorize failed: account={$this->activeAccountKey} (cred password mismatch)");
            return $this;
        }

        // Stash resolved identity and plain password for subsequent open()/createDatabase()
        $this->authUsername  = (string)($this->activeAccount['username'] ?? ($this->activeAccountKey ?? ''));
        $this->authPassword  = (string)($password ?? '');
        $this->passwordPlain = $this->authPassword; // needed for v2 encryption and for creating new DBs
        $this->authorized    = true;

        PHPDBSecurity::clearFailedLogins($this->authUsername);
        PHPDBSecurity::auditLog("Authorize success: account=" . ($this->activeAccountKey ?? 'unknown'));
        return $this;
    } catch (\Throwable $e) {
        PHPDBSecurity::auditLog('Authorize failed: cred error: ' . $e->getMessage() . ' ' . __LINE__);
        return $this;
    }
}

        
    // ---------------------------------------------------------------------
    // Credential / role / access control (phpdb.json)
    // ---------------------------------------------------------------------

    /**
     * Load phpdb.json configuration (JSON).
     * Expected shape:
     * {
     *   "encryption": "AES-256-CBC",
     *   "default_account": "admin",
     *   "accounts": {
     *     "admin": {"username":"admin","password":"...","role":"admin","databases":["*"],"can_write":true,"can_create":true}
     *   }
     * }
     */
    private function loadCredConfig(?string $credPath = null): array {
        $path = $credPath ?? $this->credPath;
        if ($path === null || trim($path) === '') {
            throw new PHPDBException('Credential file path is not set.');
        }
        if (!is_file($path)) {
            throw new PHPDBException('Credential file not found: ' . $path);
        }
        $raw = file_get_contents($path);
        if ($raw === false || trim($raw) === '') {
            throw new PHPDBException('Credential file is empty or unreadable: ' . $path);
        }
        $cfg = json_decode($raw, true);
        if (!is_array($cfg)) {
            throw new PHPDBException('Credential file must be valid JSON: ' . $path);
        }
        if (!isset($cfg['accounts']) || !is_array($cfg['accounts'])) {
            throw new PHPDBException("Credential config missing 'accounts' object.");
        }
        return $cfg;
    }

    /** Resolve an account by account-key or username; falls back to default_account. */
    private function resolveAccount(array $cfg, ?string $usernameOrKey): array {
        $accounts = $cfg['accounts'];

        if ($usernameOrKey === null || trim($usernameOrKey) === '') {
            $def = $cfg['default_account'] ?? null;
            if (!$def || !isset($accounts[$def])) {
                throw new PHPDBException("No account specified and 'default_account' is missing/invalid.");
            }
            $acc = $accounts[$def];
            $acc['_key'] = $def;
            return $acc;
        }

        $needle = trim($usernameOrKey);

        // Match by account key
        if (isset($accounts[$needle])) {
            $acc = $accounts[$needle];
            $acc['_key'] = $needle;
            return $acc;
        }

        // Match by 'username' field
        foreach ($accounts as $key => $acc) {
            if (isset($acc['username']) && is_string($acc['username']) && hash_equals($acc['username'], $needle)) {
                $acc['_key'] = $key;
                return $acc;
            }
        }

        throw new PHPDBException("Account not found for '{$needle}'.");
    }

    /** Check whether account can access the requested database name. */
    private function accountCanAccessDb(array $account, string $dbName): bool {
        $allowed = $account['databases'] ?? [];
        if (!is_array($allowed)) return false;
        $dbName = strtolower(trim($dbName));
        foreach ($allowed as $a) {
            $a = strtolower(trim((string)$a));
            if ($a === '*') return true;
            if ($a === $dbName) return true;
        }
        return false;
    }

    /** Verify a user password against an account's password/password_env in phpdb.json. */
    private function verifyAccountPassword(array $account, ?string $password): bool {
        $cfgHash = $account['password'] ?? null;
        $cfgEnv  = $account['password_env'] ?? null;

        if (($password === null || $password === '') && is_string($cfgEnv) && $cfgEnv !== '') {
            $envVal = getenv($cfgEnv);
            if ($envVal !== false) {
                $password = (string)$envVal;
            }
        }

        if ($password === null || $password === '') {
            return false;
        }

        if (is_string($cfgHash) && $cfgHash !== '') {
            $pepper = getenv('PHPDB_PEPPER');
            $ok = false;
            if ($pepper !== false && $pepper !== '') {
                $ok = password_verify($password . $pepper, $cfgHash);
            }
            if (!$ok) {
                $ok = password_verify($password, $cfgHash);
            }
            return $ok;
        }

        // No hash configured => do not allow.
        return false;
    }

/**
     * Creates a database
     * @param string $name Database name
     * @param string $path Database location path
     * @param string $charset Character set
     * @param string $collation Collation
     * @throws PHPDBException
     * @return void
     */
    public function createDatabase(string $name, string $path='', string $charset='utf-8', string $collation='utf8_general_ci'): void{if (!(bool)($this->activeAccount['can_create'] ?? false)) { throw new PHPDBException('Account is not allowed to create databases (can_create=false).'); }
    if (!$this->accountCanAccessDb($this->activeAccount, $name)) { throw new PHPDBException("Account is not allowed to create/access database '$name'."); }


// Config-driven credentials: require an active account (Authorize first)
if ($this->activeAccount === null) {
    throw new PHPDBException('No active account. Call Authorize() before createDatabase().');
}
if (!isset($this->passwordPlain) || $this->passwordPlain === '') {
    throw new PHPDBException('Missing in-memory password. Call Authorize() first (required for v2 encryption).');
}
// Apply account username/password to DB metadata
$this->authUsername = (string)($this->activeAccount['username'] ?? ($this->activeAccountKey ?? ''));
$hashedPassword = $this->hashPassword($this->passwordPlain);
$this->authPassword = (string)$this->passwordPlain;


        $name = strtolower(trim($name));
        if(!isset($this->databases[$name])){
            $this->databases[strtolower($name)] = [
                'name'=>$name,
                'extension'=>strtoupper('phpdb'),
                'path'=>parse_url($path, PHP_URL_PATH),
                'charset'=>$charset,
                'collation'=>$collation,
                'tables'=>[],
                'username'=>$this->authUsername,
                'password'=>$hashedPassword,
                'encryption_version'=>2
            ];
            if ($path !== '') {
            if (!is_dir($path) && !@mkdir($path, 0750, true)) {
                throw new PHPDBException('Failed to create database directory: ' . $path);
            }
        }
            # Encrypt and save the database file
            $this->save($name);
        }
    }
    /**
     * Creates a backup of the database
     * @param string $name Database name
     * @param string $path Backup location path
     * @return void
     */
    public function backUpDatabase(string $name, string $path= ''): void{
        $this->ensureCanView();

        $name = strtolower(trim($name));
        if(isset($this->databases[$name])){
            $db = $this->databases[$name];
            $filePath = rtrim($db['path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name . ".phpdb";
            $backupPath = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name . "_backup_" . date('Ymd_His') . ".phpdb";
            if(file_exists($filePath)){
                copy($filePath, $backupPath);
            }
        }
    }
    
    /**
     * Exports the database to a SQL/SQLite/JSON/CSV file
     * @param string $name Database name
     * @param string $format One of: json, csv, sql, sqlite
     * @return int|false Number of bytes written or false on failure
     */
    public function export(string $name, string $format = 'json'): bool|int{
        $this->ensureCanView();

        $name   = strtolower(trim($name));
        $format = strtolower(trim($format));

        // Ensure DB exists
        if (!isset($this->databases[$name])) {
            if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) {
                PHPDBSecurity::auditLog("Export failed: database '$name' not found.");
            }
            return false;
        }

        // Prepare export payload (with sensitive fields removed)
        $db = $this->databases[$name];
        unset($db['encryption_key'], $db['password'], $db['username']);

        $exportContent = '';
        switch ($format) {
            case 'sql':
                $exportContent = PHPDBUtils::exportToSQL($db);
                break;
            case 'sqlite':
                // We still produce a .sql text dump for SQLite
                $exportContent = PHPDBUtils::exportToSQLite($db);
                break;
            case 'csv':
                $exportContent = PHPDBUtils::exportToCSV($db);
                break;
            case 'json':
            default:
                $exportContent = PHPDBUtils::exportToJSON($db);
                break;
        }

        // Normalize extension for sqlite -> sql
        $targetFormat = ($format === 'sql' || $format === 'sqlite') ? 'sql' : $format;
        $targetPath   = __DIR__ . DIRECTORY_SEPARATOR . "$name.$targetFormat";

        // Audit: start
        if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) {
            PHPDBSecurity::auditLog("Export started: name=$name, format=$format => $targetFormat, target=$targetPath");
        }

        // Write file
        $bytes = @file_put_contents($targetPath, $exportContent);

        // Audit: success/failure
        if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) {
            if ($bytes === false) 
                PHPDBSecurity::auditLog("Export failed: name=$name, target=$targetPath");
            else 
                PHPDBSecurity::auditLog("Export completed: name=$name, bytes=$bytes, target=$targetPath");
        }

        return $bytes;
    }

    
   
    /**
     * Import JSON/MySQL/SQLite/CSV to phpdb
     * @param string $path Path to the source file OR path-without-extension (stem).
     *                     The resulting .phpdb will be saved in the same directory.
     * @param string $format Format of the import file (json, sql, sqlite, csv).
     *                       If $path is a full file path with a known extension, this will be auto-inferred.
     * @return int|false Number of bytes written to the .phpdb file, or false on failure
     * @throws PHPDBException
     */
    public function import(string $path, string $format = "json"): bool|int{
        if (! (bool) ($this->activeAccount['can_create'] ?? false)) {
            throw new PHPDBException('Import operation denied: account is not allowed to create databases.');
        }

        $path   = trim($path);
        $format = strtolower(trim($format));
        if ($path === '') {
            throw new PHPDBException("Import path must not be empty.");
        }

        // If a full file path exists, use it directly and infer format from extension.
        $ext      = strtolower((string)pathinfo($path, PATHINFO_EXTENSION));
        $isFile   = is_file($path);
        $baseDir  = '';
        $stem     = '';
        $name     = ''; // database name / output file stem
        $inputPath= null;

        // Map common extensions to formats
        $extToFormat = [
            'json'   => 'json',
            'csv'    => 'csv',
            'sql'    => 'sql',     // used by both MySQL and SQLite dump styles
            'sqlite' => 'sqlite',
            'db'     => 'sqlite'   // optional convenience
        ];

        if ($isFile) {
            // Full file path case
            $inputPath = $path;
            $baseDir   = dirname($path);
            $stem      = (string)pathinfo($path, PATHINFO_FILENAME);
            $name      = strtolower($stem);

            if (isset($extToFormat[$ext])) {
                $format = $extToFormat[$ext]; // override format based on actual file extension
            } else {
                // keep user-supplied $format but sanity-check
                if (!in_array($format, ['json','csv','sql','sqlite'], true)) {
                    throw new PHPDBException("Unknown file extension '$ext' and unsupported format '$format'.");
                }
            }
        } else {
            // Not a file: treat $path as either a stem path (folder + filename without extension),
            // or a folder path (require stem via basename).
            $candidateDir = is_dir($path) ? rtrim($path, DIRECTORY_SEPARATOR) : dirname($path);
            $candidateDir = $candidateDir === '' ? '.' : $candidateDir;

            // Determine stem
            $stem = is_dir($path)
                ? (string)basename($path) // if user passed folder only, basename is folder name; they likely intend folder + separate stem
                : (string)pathinfo($path, PATHINFO_FILENAME);

            if ($stem === '' || $stem === '.' || $stem === DIRECTORY_SEPARATOR) {
                throw new PHPDBException("Provide a file stem (without extension) or a full file path.");
            }

            $name    = strtolower($stem);
            $baseDir = $candidateDir;

            // Build candidates in the provided directory
            $candidates = [];
            switch ($format) {
                case 'json':
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.json';
                    break;
                case 'csv':
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.csv';
                    break;
                case 'sql':
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.sql';
                    break;
                case 'sqlite':
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.sqlite';
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.db';
                    $candidates[] = $baseDir . DIRECTORY_SEPARATOR . $stem . '.sql'; // accept SQLite SQL dump
                    break;
                default:
                    throw new PHPDBException("Unsupported import format: $format");
            }

            foreach ($candidates as $p) {
                if (is_file($p)) { $inputPath = $p; break; }
            }
            if ($inputPath === null) {
                throw new PHPDBException("Import source file not found in '$baseDir' for stem '$stem' (format '$format').");
            }
        }

        // Optional: canonicalize and restrict path if your security policy requires it
        if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity') && method_exists(PHPDBSecurity::class, 'canonicalPath')) {
            $canon = PHPDBSecurity::canonicalPath($inputPath);
            if ($canon === null) throw new PHPDBException("Invalid import path.");
            $inputPath = $canon;
            $canonDir  = PHPDBSecurity::canonicalPath($baseDir);
            if ($canonDir !== null) $baseDir = $canonDir;
        }

        // Read source
        $raw = file_get_contents($inputPath);
        if ($raw === false) {
            throw new PHPDBException("Failed to read import file: $inputPath");
        }

        // Delegate parsing to PHPDBUtils
        switch ($format) {
            case 'json':
                $dbStruct = PHPDBUtils::importFromJSON($raw, $name);
                break;
            case 'csv':
                $dbStruct = PHPDBUtils::importFromCSV($raw, $name);
                break;
            case 'sql':
                $dbStruct = PHPDBUtils::importFromSQL($raw, $name);
                break;
            case 'sqlite':
                $dbStruct = PHPDBUtils::importFromSQLite($raw, $name);
                break;
            default:
                throw new PHPDBException("Unsupported import format: $format");
        }

        // Build internal database entry and save to the same directory
        $this->databases[$name] = [
            'name'           => (string)($dbStruct['name']      ?? $name),
            'extension'      => strtoupper('phpdb'),
            'path'           => $baseDir, // save alongside the source directory
            'charset'        => (string)($dbStruct['charset']   ?? 'utf-8'),
            'collation'      => (string)($dbStruct['collation'] ?? 'utf8_general_ci'),
            'tables'         => (array) ($dbStruct['tables']    ?? []),
            'username'       => $this->authUsername,
            'password' => $this->authPassword,
            'encryption_version' => 2
        ];

        if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) 
            PHPDBSecurity::auditLog("Import started: name=$name, format=$format, source=$inputPath");
        

        $this->save($name);

        if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) 
            PHPDBSecurity::auditLog("Import completed: name=$name");
        

        // Return bytes written
        $filePath = rtrim($this->databases[$name]['path'], DIRECTORY_SEPARATOR)
                . DIRECTORY_SEPARATOR . "$name.phpdb";
        return is_file($filePath) ? filesize($filePath) : false;
    }



    /**
     * Restores a database from a backup file
     * @param string $name Database name
     * @param string $backupFilePath Backup file path
     * @return void
     */
    public function restoreDatabase(string $name, string $backupFilePath): void{$this->ensureCanDelete();

        $name = strtolower(trim($name));
        if(isset($this->databases[$name])){
            $db = $this->databases[$name];
            $filePath = rtrim($db['path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name . ".phpdb";
            if(file_exists($backupFilePath)){
                copy($backupFilePath, $filePath);
            }
        }
    }

/**
 * Hash a password (optionally with a server-side pepper).
 *
 * If you set an environment variable PHPDB_PEPPER, it will be appended to the password
 * before hashing/verifying. Keep the pepper secret (e.g., in env/secret manager).
 */
private function hashPassword(string $password): string {
    $pepper = getenv('PHPDB_PEPPER');
    if ($pepper !== false && $pepper !== '') {
        $password = "$password$pepper";
    }
    // PASSWORD_DEFAULT keeps you updated as PHP evolves.
    return password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
}

/**
 * Verify a password against a stored password_hash.
 *
 * Backward compatibility:
 * - If PHPDB_PEPPER is set, we try (password+pepper) first.
 * - If that fails, we fall back to verifying the raw password (supports legacy hashes).
 */
private function verifyPassword(string $password, string $hash): bool {
    $pepper = getenv('PHPDB_PEPPER');
    if ($pepper !== false && $pepper !== '') {
        if (password_verify($password . $pepper, $hash)) return true;
    }
    return password_verify($password, $hash);
}
/**
 * Ensure the current active account has write permissions; throw otherwise.
 */
private function ensureCanWrite(): void {
    if (!(bool)($this->activeAccount['can_write'] ?? false)) {
        throw new PHPDBException('Write operation denied: account is read-only.');
    }
}

    /**
     * Ensure the current active account has view permissions; throw otherwise.
     */
    private function ensureCanView(): void {
        if (! (bool) ($this->activeAccount['can_view'] ?? false)) {
            throw new PHPDBException('View operation denied: account is not allowed to view.');
        }
    }

    /**
     * Ensure the current active account has delete permissions; throw otherwise.
     */
    private function ensureCanDelete(): void {
        if (! (bool) ($this->activeAccount['can_delete'] ?? false)) {
            throw new PHPDBException('Delete operation denied: account is not allowed to delete.');
        }
    }

    // ----------------------------------------------------------------------
    // Safe condition evaluation (replaces eval-based condition parsing)
    // Supports: =, ==, !=, <>, >, <, >=, <=, IS (NOT) NULL, AND/OR/NOT, parentheses,
    // identifiers (column names), string/number literals, TRUE/FALSE/NULL.
    // ----------------------------------------------------------------------
    private function evaluateCondition(array $row, string $cond): bool{
        $cond = trim($cond);
        if ($cond === '') return true;

        $tokens = $this->tokenizeCondition($cond);
        if ($tokens === null || $tokens === []) return false;

        $pos = 0;
        $val = $this->parseCondOr($tokens, $pos, $row);
        if ($val === null) return false;
        if ($pos !== count($tokens)) return false;
        return (bool)$val;
    }

    private function tokenizeCondition(string $s): ?array{
        $len = strlen($s);
        $i = 0;
        $out = [];

        $push = function(string $type, $value) use (&$out): void {
            $out[] = ['t' => $type, 'v' => $value];
        };

        while ($i < $len) {
            $ch = $s[$i];

            // whitespace
            if ($ch <= " ") { $i++; continue; }

            // parentheses
            if ($ch === '(' || $ch === ')') {
                $push('paren', $ch);
                $i++;
                continue;
            }

            // operators (2-char first)
            $two = ($i + 1 < $len) ? ($ch . $s[$i+1]) : '';
            if (in_array($two, ['>=','<=','!=','<>','=='], true)) {
                $push('op', $two);
                $i += 2;
                continue;
            }
            if (in_array($ch, ['=','>','<'], true)) {
                $push('op', $ch);
                $i++;
                continue;
            }

            // quoted string
            if ($ch === "'" || $ch === '"') {
                $quote = $ch;
                $i++;
                $buf = '';
                while ($i < $len) {
                    $c = $s[$i];
                    if ($c === '\\') {
                        // backslash escape
                        if ($i + 1 < $len) {
                            $buf .= $s[$i+1];
                            $i += 2;
                            continue;
                        }
                        $i++;
                        continue;
                    }
                    if ($c === $quote) {
                        $i++;
                        break;
                    }
                    $buf .= $c;
                    $i++;
                }
                $push('str', $buf);
                continue;
            }

            // number (int/float)
            if (ctype_digit($ch) || ($ch === '.' && $i + 1 < $len && ctype_digit($s[$i+1]))) {
                $start = $i;
                $i++;
                while ($i < $len && (ctype_digit($s[$i]) || $s[$i] === '.')) $i++;
                $num = substr($s, $start, $i - $start);
                $push('num', $num);
                continue;
            }

            // identifier / keyword
            if (ctype_alpha($ch) || $ch === '_') {
                $start = $i;
                $i++;
                while ($i < $len) {
                    $c = $s[$i];
                    if (ctype_alnum($c) || $c === '_') { $i++; continue; }
                    break;
                }
                $word = substr($s, $start, $i - $start);
                $upper = strtoupper($word);
                if (in_array($upper, ['AND','OR','NOT','IS','NULL','TRUE','FALSE'], true)) {
                    $push('kw', $upper);
                } else {
                    $push('ident', $word);
                }
                continue;
            }

            // Unknown char => reject
            return null;
        }

        return $out;
    }

    private function parseCondOr(array $t, int &$pos, array $row): ?bool{
        $left = $this->parseCondAnd($t, $pos, $row);
        if ($left === null) return null;
        while ($pos < count($t) && $t[$pos]['t'] === 'kw' && $t[$pos]['v'] === 'OR') {
            $pos++;
            $right = $this->parseCondAnd($t, $pos, $row);
            if ($right === null) return null;
            $left = (bool)$left || (bool)$right;
        }
        return (bool)$left;
    }

    private function parseCondAnd(array $t, int &$pos, array $row): ?bool{
        $left = $this->parseCondNot($t, $pos, $row);
        if ($left === null) return null;
        while ($pos < count($t) && $t[$pos]['t'] === 'kw' && $t[$pos]['v'] === 'AND') {
            $pos++;
            $right = $this->parseCondNot($t, $pos, $row);
            if ($right === null) return null;
            $left = (bool)$left && (bool)$right;
        }
        return (bool)$left;
    }

    private function parseCondNot(array $t, int &$pos, array $row): ?bool{
        if ($pos < count($t) && $t[$pos]['t'] === 'kw' && $t[$pos]['v'] === 'NOT') {
            $pos++;
            $v = $this->parseCondNot($t, $pos, $row);
            if ($v === null) return null;
            return !((bool)$v);
        }
        return $this->parseCondCompare($t, $pos, $row);
    }

    private function parseCondCompare(array $t, int &$pos, array $row): ?bool{
        $left = $this->parseCondPrimary($t, $pos, $row);

        // IS (NOT) NULL
        if ($pos < count($t) && $t[$pos]['t'] === 'kw' && $t[$pos]['v'] === 'IS') {
            $pos++;
            $neg = false;
            if ($pos < count($t) && $t[$pos]['t'] === 'kw' && $t[$pos]['v'] === 'NOT') {
                $neg = true;
                $pos++;
            }
            if ($pos >= count($t) || $t[$pos]['t'] !== 'kw' || $t[$pos]['v'] !== 'NULL') return null;
            $pos++;
            $isNull = ($left === null);
            return $neg ? !$isNull : $isNull;
        }

        // comparison operator
        if ($pos < count($t) && $t[$pos]['t'] === 'op') {
            $op = $t[$pos]['v'];
            $pos++;
            $right = $this->parseCondPrimary($t, $pos, $row);
            if ($op === '=') $op = '==';
            if ($op === '<>') $op = '!=';
            return $this->compareValues($left, $right, $op);
        }

        // no operator: treat primary as boolean-ish
        return (bool)$left;
    }

    private function parseCondPrimary(array $t, int &$pos, array $row){
        if ($pos >= count($t)) return null;
        $tok = $t[$pos];

        if ($tok['t'] === 'paren' && $tok['v'] === '(') {
            $pos++;
            $v = $this->parseCondOr($t, $pos, $row);
            if ($v === null) return null;
            if ($pos >= count($t) || $t[$pos]['t'] !== 'paren' || $t[$pos]['v'] !== ')') return null;
            $pos++;
            return $v;
        }

        $pos++;
        if ($tok['t'] === 'ident') {
            $k = $tok['v'];
            return array_key_exists($k, $row) ? $row[$k] : null;
        }
        if ($tok['t'] === 'str') return $tok['v'];
        if ($tok['t'] === 'num') {
            $n = $tok['v'];
            return (strpos($n, '.') !== false) ? (float)$n : (int)$n;
        }
        if ($tok['t'] === 'kw') {
            if ($tok['v'] === 'NULL') return null;
            if ($tok['v'] === 'TRUE') return true;
            if ($tok['v'] === 'FALSE') return false;
        }

        return null;
    }

    private function compareValues($a, $b, string $op): bool{
        if ($a === null || $b === null) {
            if ($op === '==') return $a === null && $b === null;
            if ($op === '!=') return !($a === null && $b === null);
            return false;
        }

        if (is_bool($a) || is_bool($b)) {
            $aa = (bool)$a;
            $bb = (bool)$b;
            return match ($op) {
                '==' => $aa === $bb,
                '!=' => $aa !== $bb,
                '>'  => (int)$aa > (int)$bb,
                '<'  => (int)$aa < (int)$bb,
                '>=' => (int)$aa >= (int)$bb,
                '<=' => (int)$aa <= (int)$bb,
                default => false,
            };
        }

        if (is_numeric($a) && is_numeric($b)) {
            $aa = $a + 0;
            $bb = $b + 0;
            return match ($op) {
                '==' => $aa == $bb,
                '!=' => $aa != $bb,
                '>'  => $aa > $bb,
                '<'  => $aa < $bb,
                '>=' => $aa >= $bb,
                '<=' => $aa <= $bb,
                default => false,
            };
        }

        $aa = (string)$a;
        $bb = (string)$b;
        $cmp = strcmp($aa, $bb);
        return match ($op) {
            '==' => $cmp === 0,
            '!=' => $cmp !== 0,
            '>'  => $cmp > 0,
            '<'  => $cmp < 0,
            '>=' => $cmp >= 0,
            '<=' => $cmp <= 0,
            default => false,
        };
    }

    /**
     * Convert a value to a UNIX timestamp if it looks like a date/time.
     * Supports DateTimeInterface and common ISO formats:
     *  - YYYY-MM-DD
     *  - YYYY-MM-DD HH:MM:SS
     *  - YYYY-MM-DDTHH:MM:SS
     */
    private function toTimestampIfDateTime($v): ?int{
        if ($v instanceof \DateTimeInterface) {
            return $v->getTimestamp();
        }
        if (!is_string($v)) return null;
        $s = trim($v);
        if (preg_match('/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?$/', $s) !== 1) {
            return null;
        }
        $ts = strtotime($s);
        return ($ts === false) ? null : (int)$ts;
    }





// ---- v2 file format (stronger auth + encryption) ---------------------------------
private const FILE_MAGIC_V2 = 'PHPDBv2';
private const KDF_ITERATIONS = 200000; // PBKDF2 iterations (tune for your server)

/**
 * Derive encryption + MAC keys from password using PBKDF2.
 * Returns [encKey(32 bytes), macKey(32 bytes)].
 */
private function deriveKeys(string $password, string $salt, int $iterations = self::KDF_ITERATIONS): array {
    $pepper = getenv('PHPDB_PEPPER');
    if ($pepper !== false && $pepper !== '') {
        $password = "$password$pepper";
    }
    $material = hash_pbkdf2('sha256', $password, $salt, $iterations, 64, true);
    $encKey = substr($material, 0, 32);
    $macKey = substr($material, 32, 32);
    return [$encKey, $macKey];
}

/** base64url encode (RFC 4648) */
private function b64urlEncode(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

/** base64url decode (RFC 4648) */
private function b64urlDecode(string $str): string {
    $b64 = strtr($str, '-_', '+/');
    $pad = \strlen($b64) % 4;
    if ($pad > 0) $b64 .= str_repeat('=', 4 - $pad);
    $out = base64_decode($b64, true);
    return $out === false ? '' : $out;
}

    /**
     * Creates an random encryption key which is used to encrypt/decrypt .phpdb files.
     * @return string The generated encryption key.
     */
    private function generateEncryptionKey(): string{
        // Prefer CSPRNG provided by PHP
        return bin2hex(random_bytes(16));
    }
    /**
     * Sanitizes base64
     * @param string $base64 The base64 string to sanitize.
     * @return string The sanitized base64 string.
     */
    private function sanitizeBase64(string $base64): string{
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }

    /**
     * Checks whether a string is a PHP serialized value.
     * @param string $str
     * @return bool
     */
    private function isSerialized(string $str): bool{
        if($str === '') return false;
        // common serialized prefixes: s: a: O: i: d: b: N;
        $first = $str[0];
        if(!\in_array($first, ['s','a','O','i','d','b','N'], true)) return false;
        $un = @unserialize($str, ['allowed_classes' => false]);
        return $un !== false || $str === 'b:0;';
    }

    /**
     * Returns the un sanitized base64 encode
     * @param string $sanitizedBase64 Sanitized base64 string
     * @return string The un sanitized base64 string.
     */
    private function getSanitizedBase64(string $sanitizedBase64): string{
        $base64 = str_replace(['-', '_'], ['+', '/'], $sanitizedBase64);
        $padding = \strlen($base64) % 4;
        if($padding > 0){
            $base64 .= str_repeat('=', 4 - $padding);
        }
        return base64_decode($base64);
    }

    /**
     * Atomically write a database file to reduce corruption risk on crashes.
     *
     * Strategy:
     * - Copy the current file to a .bak (best-effort)
     * - Write new contents to a .tmp file
     * - Rename .tmp over the target (atomic on most filesystems)
     *
     * @throws PHPDBException
     */
    private function atomicWrite(string $filePath, string $content): void{
        $tmpPath = $filePath . '.tmp';
        $bakPath = $filePath . '.bak';

        // Best-effort backup of the last known-good file
        if (is_file($filePath)) {
            @copy($filePath, $bakPath);
        }

        $bytes = @file_put_contents($tmpPath, $content, LOCK_EX);
        if ($bytes === false) {
            throw new PHPDBException('Failed to write temporary database file: ' . $tmpPath);
        }

        // Atomic replace (rename is atomic on POSIX when on same filesystem)
        if (!@rename($tmpPath, $filePath)) {
            // Fallback: write directly and remove tmp
            $bytes2 = @file_put_contents($filePath, $content, LOCK_EX);
            @unlink($tmpPath);
            if ($bytes2 === false) {
                throw new PHPDBException("Failed to write database file: $filePath");
            }
        }
    }

    /**
 * Save the database.
 *
 * Supports:
 * - v2 (default): password-derived key (PBKDF2) + random salt/iv + HMAC integrity
 * - v1 (legacy): stored key in file (kept for backward compatibility)
 */
private function save(string $name): void{
    if (str_contains($name, '/') || str_contains($name, '\\')) {
        $name = basename($name, '.phpdb');
    }

    $dbKey = strtolower($name);
    $db = $this->databases[$dbKey];

    $filePath = isset($this->databases[$dbKey])
        ? (rtrim($this->databases[$dbKey]['path'], DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . $dbKey . ".phpdb")
        : "$dbKey.phpdb";

    $data = serialize($db);
    // Map DB charset to mbstring-friendly name and convert payload
    $toEnc = PHPDBUtils::mbTargetEncoding($db['charset'] ?? 'UTF-8');
    $fromEnc = mb_detect_encoding($data, ['UTF-8','ISO-8859-1','Windows-1252'], true) ?: 'UTF-8';
    $payload = mb_convert_encoding($data, $toEnc, $fromEnc);

    $version = (int)($db['encryption_version'] ?? 1);

    // ---- v2: password-derived key + integrity protection ----
    if ($version >= 2) {
        if (!isset($this->passwordPlain) || $this->passwordPlain === '') {
            throw new PHPDBException('Cannot save: missing in-memory password (passwordPlain).');
        }
        $salt = random_bytes(16);
        $iv = random_bytes(16);
        [$encKey, $macKey] = $this->deriveKeys($this->passwordPlain, $salt);

        $cipherRaw = openssl_encrypt($payload, $this->encryptionType, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($cipherRaw === false) {
            throw new PHPDBException('Encryption failed while saving database.');
        }
        $mac = hash_hmac('sha256', "$salt$iv$cipherRaw", $macKey, true);

        $content = self::FILE_MAGIC_V2 . ':'
            . $this->b64urlEncode($salt) . ':'
            . $this->b64urlEncode($iv) . ':'
            . $this->b64urlEncode($mac) . ':'
            . $this->b64urlEncode($cipherRaw);

        $this->atomicWrite($filePath, $content);
        return;
    }

    // ---- v1 (legacy): stored key in file (less secure; retained for compatibility) ----
    if (!isset($db['encryption_key']) || !\is_string($db['encryption_key']) || $db['encryption_key'] === '') {
        $db['encryption_key'] = $this->generateEncryptionKey();
        $this->databases[$dbKey]['encryption_key'] = $db['encryption_key'];
    }

    // Use a 16-byte binary IV from first 32 hex chars of the key
    $ivHex = substr($db['encryption_key'], 0, 32);
    $iv = hex2bin($ivHex);
    $encryptedData = openssl_encrypt(
        $payload,
        $this->encryptionType,
        $db['encryption_key'],
        0,
        $iv
    );

    file_put_contents(
        $filePath,
        $this->sanitizeBase64(base64_encode($db['encryption_key'])) . "/" . $encryptedData,
        LOCK_EX
    );
}

    /**
     * Opens the database
     * @param string $name Database name or path
     * @return bool True if the database was opened successfully, false otherwise
     */
    public function open(string $name): bool{
    $name = strtolower(trim($name));
    if ($name === '') {
        return false;
    }
    if (hash_equals($this->openDB, $name)) {
        throw new PHPDBException('Database is already open. Make sure you close it before opening again.');
    }
    // Must be authorized first (account + password validated via Authorize())
    if (!$this->authorized || $this->activeAccount === null || $this->authUsername === null || $this->authPassword === null) {
        PHPDBSecurity::auditLog("Open blocked (not authorized): name=$name");
        return false;
    }
        // Enforce view permission
        if (! (bool) ($this->activeAccount['can_view'] ?? false)) {
            PHPDBSecurity::auditLog("Open denied: account={$this->activeAccountKey} (can_view=false)");
            return false;
        }


    // Enforce DB-level access policy here (since DB may not exist at Authorize time)
    if (!$this->accountCanAccessDb($this->activeAccount, $name)) {
        PHPDBSecurity::auditLog("Open denied: account={$this->activeAccountKey} db={$name} (not allowed)");
        return false;
    }

    // Determine file path. Accept a full file path, or a known DB name.
    $nameKey = strtolower($name);
    is_file($name) && strtolower((string)pathinfo($name, PATHINFO_EXTENSION)) === 'phpdb'
        ? $filePath = $name
        : $filePath = isset($this->databases[$nameKey])
            ? (rtrim($this->databases[$nameKey]['path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name . '.phpdb')
            : "$name.phpdb";

    if (!file_exists($filePath)) {
        // DB doesn't exist yet -> caller can createDatabase() separately (subject to can_create)
        PHPDBSecurity::auditLog("Open failed: database file not found: $filePath");
        return false;
    }

    // Read and decrypt .phpdb
    $raw = file_get_contents($filePath);
    if ($raw === false || $raw === '') {
        PHPDBSecurity::recordFailedLogin($this->authUsername);
        return false;
    }
    $raw = trim($raw);
    $results = null;

    // ---- v2 file format ----
    if (str_starts_with($raw, self::FILE_MAGIC_V2 . ':')) {
        $parts = explode(':', $raw, 5);
        if (count($parts) !== 5) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        [, $saltB64, $ivB64, $macB64, $cipherB64] = $parts;
        $salt = $this->b64urlDecode($saltB64);
        $iv   = $this->b64urlDecode($ivB64);
        $mac  = $this->b64urlDecode($macB64);
        $cipherRaw = $this->b64urlDecode($cipherB64);
        if ($salt === '' || $iv === '' || $mac === '' || $cipherRaw === '') { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        [$encKey, $macKey] = $this->deriveKeys($this->authPassword, $salt);
        $calc = hash_hmac('sha256', "$salt$iv$cipherRaw", $macKey, true);
        if (!PHPDBSecurity::timingSafeEquals($calc, $mac)) {
            PHPDBSecurity::recordFailedLogin($this->authUsername); return false;
        }
        
        $decrypted = openssl_decrypt($cipherRaw, $this->encryptionType, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false || $decrypted === '') { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $results = @unserialize($decrypted, ['allowed_classes' => false]);
        if (!\is_array($results) || !isset($results['username'], $results['password'], $results['name'])) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }

        // Authenticate (constant-time username check, uniform failure path)
        $dummyHash  = '$2y$12$C6UzMDM.H6dfI/f/IKcEeO9y3lGkz6tN8vD7ZrJmM5YpXz.3n/7QW';
        $storedUser = (string)$results['username'];
        $storedHash = (string)$results['password'];

        

        $userOk = PHPDBSecurity::timingSafeEquals($storedUser, $this->authUsername);
        $passOk = $this->verifyPassword($this->authPassword, $userOk ? $storedHash : $dummyHash);
        if (!$userOk || !$passOk) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }

        // Success: store in-memory password for future saves, clear lockout
        $this->passwordPlain = (string)$this->authPassword;
        PHPDBSecurity::clearFailedLogins($this->authUsername);

        // Rehash if needed (e.g., PHP upgrade or pepper added)
        $pepper = getenv('PHPDB_PEPPER');
        $rehashPassword = ($pepper !== false && $pepper !== '') ? ($this->authPassword . $pepper) : $this->authPassword;
        if (password_needs_rehash($storedHash, PASSWORD_DEFAULT, ['cost' => 12])) {
            $results['password'] = password_hash($rehashPassword, PASSWORD_DEFAULT, ['cost' => 12]);
        }
        $results['encryption_version'] = 2;
    }
    // ---- v1 legacy file format ----
    else {
        $parts = explode('/', $raw, 2);
        if (count($parts) !== 2) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $key = $this->getSanitizedBase64($parts[0]);
        if (!is_string($key) || $key === '') { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $ivHex = substr($key, 0, 32);
        $iv    = hex2bin($ivHex);
        $decryptedData = openssl_decrypt($parts[1], $this->encryptionType, $key, 0, $iv);
        if ($decryptedData === false || $decryptedData === '') { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $results = @unserialize($decryptedData, ['allowed_classes' => false]);
        if (!is_array($results) || !isset($results['username'], $results['password'], $results['name'])) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $dummyHash  = '$2y$12$C6UzMDM.H6dfI/f/IKcEeO9y3lGkz6tN8vD7ZrJmM5YpXz.3n/7QW';
        $storedUser = (string)$results['username'];
        $storedHash = (string)$results['password'];
        $userOk = PHPDBSecurity::timingSafeEquals($storedUser, $this->authUsername);
        $passOk = $this->verifyPassword($this->authPassword, $userOk ? $storedHash : $dummyHash);
        if (!$userOk || !$passOk) { PHPDBSecurity::recordFailedLogin($this->authUsername); return false; }
        $this->passwordPlain = (string)$this->authPassword;
        PHPDBSecurity::clearFailedLogins($this->authUsername);
        // Auto-migrate legacy v1 files to v2 on successful login
        $results['encryption_version'] = 2;
        if (isset($results['encryption_key'])) unset($results['encryption_key']);
    }

    // At this point we have an authenticated, decrypted DB structure
    $dbKey = strtolower((string)$results['name']);
    $this->databases[$dbKey] = $results;
    $this->openDB = $dbKey;

    // Persist any rehash/migration updates by saving immediately — only if account can write
    $canWrite = (bool)($this->activeAccount['can_write'] ?? false);
    if ((int)($results['encryption_version'] ?? 1) >= 2 && $canWrite) {
        $this->save($dbKey);
    }

    PHPDBSecurity::auditLog("Open success: name=$dbKey, user=" . ($this->authUsername ?? 'unknown') . ", v=" . ($results['encryption_version'] ?? 1) . ", write=" . ($canWrite ? 'yes' : 'no'));

    // Consume authorization (one-time) so another DB requires re-authorization
    $this->authorized = false;
    $this->authUsername = null;
    $this->authPassword = null;
    $this->authorizedPayload = null;
    $this->authorizedDbKey = null;
    return true;
}


    /**
     * Delete the database
     * @param string $name Database name or path
     * @return void
     */
    public function dropDatabase(string $name): void{$this->ensureCanDelete();
        if (! $this->accountCanAccessDb($this->activeAccount ?? [], $name)) {
            throw new PHPDBException("Account is not allowed to delete/access database '$name'.");
        }

            $filePath = isset($this->databases[strtolower($name)]) ? (rtrim($this->databases[strtolower($name)]['path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name . '.phpdb'):"$name.phpdb";
            if(file_exists($filePath)){
                unlink($filePath);
                unset($this->databases[strtolower($name)]);
            }
        
    }
    /**
     * Closes the opened database
     * @return void
      *
 * @param string $name Database name
 */
    public function close(string $name): void{
        if($name !== ''){
            if(hash_equals($this->openDB, $name)){
                $this->save($name);
                $this->openDB = '';
            }
        }
    }
    /**
     * Creates a table in the specified database.
     * @param string $tableName Table name
     * @param array $columns Columns definition as associative array (column_name => definition)
     * @throws PHPDBException Database does not exist.
     * @return void
     */
    public function createTable( string $tableName, array $columns): void{
        $this->ensureCanWrite();

        if($this->openDB === '')
            throw new PHPDBException("Database '$this->openDB' is not open. Please open the database before creating a table.");
        $dbKey = strtolower($this->openDB);
        if(isset($this->databases[$dbKey])){
            if(!isset($this->databases[$dbKey]['tables'][strtolower($tableName)])){
                $this->databases[$dbKey]['tables'][strtolower($tableName)] = [
                    'name'=>$tableName,
                    'columns'=>$columns,
                    'rows'=>[]
                ];
                $this->save($this->openDB);
            }
        }
    }
    
    /**
     * Checks whether a table exists in the currently opened database (case-insensitive).
     *
     * @param string $tableName Table name to check.
     * @return bool TRUE if the table exists, FALSE otherwise.
     * @throws PHPDBException If the database is not open or does not exist, or if view permission is denied.
     */
    public function tableExists(string $tableName): bool{
        // Require view permission (consistent with listTables/fetchAll)
        $this->ensureCanView();

        // Must have a DB open
        if ($this->openDB === '') {
            throw new PHPDBException("Database '{$this->openDB}' is not open. Please open the database before checking table existence.");
        }

        $dbKey = strtolower($this->openDB);
        if (!isset($this->databases[$dbKey])) {
            throw new PHPDBException("Database '{$this->openDB}' does not exist.");
        }

        // Tables are stored with lowercased keys
        $tableKey = strtolower($tableName);
        return isset($this->databases[$dbKey]['tables'][$tableKey]);
    }

    /**
     * Drops table from database
     * @param string $tableName Table name
     * @throws PHPDBException Database or table does not exist.
     * @return void
     */
    public function dropTable( string $tableName ): void{
        $this->ensureCanDelete();
       if($this->openDB === '')
            throw new PHPDBException("Database '$this->openDB' is not open. Please open the database before dropping a table.");
        $dbKey = strtolower($this->openDB);
        if(isset($this->databases[$dbKey])){
            if(isset($this->databases[$dbKey]['tables'][strtolower($tableName)])){
                unset($this->databases[$dbKey]['tables'][strtolower($tableName)]);
                $this->save($this->openDB);
            }else{
                throw new PHPDBException("Table '$tableName' does not exist in database '$this->openDB'.");
            }
        }
        else{
            throw new PHPDBException("Database '$this->openDB' does not exist.");
        }
    }
    /**
     * Renames a table
     * @param string $oldName The current table name
     * @param string $newName The new table name
     * @throws PHPDBException Database or table does not exist.
     * @return void
     */
    public function renameTable( string $oldName, string $newName ): void{
        $this->ensureCanWrite();

        if($this->openDB === "")
            throw new PHPDBException("Database '$this->openDB' is not open. Please open the database before renaming a table.");
        $dbKey = strtolower($this->openDB);
        if(isset($this->databases[$dbKey])){
            if(isset($this->databases[$dbKey]['tables'][strtolower($oldName)])){
                $tableData = $this->databases[$dbKey]['tables'][strtolower($oldName)];
                unset($this->databases[$dbKey]['tables'][strtolower($oldName)]);
                $tableData['name'] = $newName;
                $this->databases[$dbKey]['tables'][strtolower($newName)] = $tableData;
                $this->save($this->openDB);
            }else{
                throw new PHPDBException("Table '$oldName' does not exist in database '$this->openDB'.");
            }
        }
        else{
            throw new PHPDBException("Database '$this->openDB' does not exist.");
        }
    }
/**
 * List all tables in the currently opened database.
 *
 * @return array Array of table names (lowercased keys)
 */

    public function listTables(): array{
        $this->ensureCanView();

        $dbName = $this->openDB;
        $dbKey = strtolower($dbName);
        if(isset($this->databases[$dbKey])){
            return array_keys($this->databases[$dbKey]['tables']);
        }
        return [];
    }
    /**
     * Inserts item into table while also validates the data values base off the columns and the charset
     * @param string $tableName Table name
     * @param array $data Data to insert
     * @throws PHPDBException Database or table does not exist.
     * @return void
     */
    public function insert(string $tableName, array $data): void{
        $this->ensureCanWrite();

        if($this->openDB === "") 
            throw new PHPDBException("Database '$this->openDB' is not open. Please open the database before inserting data.");
        $dbKey = strtolower($this->openDB);
        if(isset($this->databases[$dbKey])){
            if(isset($this->databases[$dbKey]['tables'][strtolower($tableName)])){
                $table = &$this->databases[$dbKey]['tables'][strtolower($tableName)];
                $columns = $table['columns'];
                $row = [];
                $targetCharset = $this->databases[$dbKey]['charset'] ?? 'UTF-8';
                $uniqueColumns = [];

                // generate next auto-increment values for integer primary keys and validate many MySQL types
                foreach($columns as $colName => $colDef){
                    $def = (string)$colDef;
                    $defUpper = strtoupper($def);
                    $tokens = preg_split('/\W+/', $defUpper, -1, PREG_SPLIT_NO_EMPTY);
                    $hasNotNull = strpos($defUpper, 'NOT NULL') !== false;
                    $isAuto = strpos($defUpper, 'AUTO_INCREMENT') !== false;
                    $isVarchar = \in_array('VARCHAR', $tokens, true);
                    $maxLen = null;
                    if($isVarchar && preg_match('/\((\d+)\)/', $def, $vMatches) === 1){
                        $maxLen = (int)$vMatches[1];
                    }

                    // extended type recognition using token list to avoid raw SQL words in regex
                    $isInt = \count(array_intersect($tokens, ['TINYINT','SMALLINT','MEDIUMINT','INT','BIGINT'])) > 0;
                    $isBool = \in_array('BOOL', $tokens, true) || \in_array('BOOLEAN', $tokens, true) ||
                              \in_array('TINYINT', $tokens, true) && preg_match('/\((\d+)\)/', $def, $pm) === 1 && isset($pm[1]) && (int)$pm[1] === 1;
                    $isFloat = \count(array_intersect($tokens, ['FLOAT','DOUBLE','DECIMAL'])) > 0;
                    $isDateTime = \count(array_intersect($tokens, ['DATETIME','TIMESTAMP'])) > 0;
                    $isDate = \in_array('DATE', $tokens, true) && !$isDateTime;
                    $isTime = \in_array('TIME', $tokens, true);
                    $isYear = \in_array('YEAR', $tokens, true);
                    $isText = \count(array_intersect($tokens, ['TEXT','TINYTEXT','MEDIUMTEXT','LONGTEXT'])) > 0;
                    $isBlob = \count(array_intersect($tokens, ['BLOB','TINYBLOB','MEDIUMBLOB','LONGBLOB'])) > 0;
                    $isBinary = \count(array_intersect($tokens, ['VARBINARY','BINARY'])) > 0;
                    $isEnum = \in_array('ENUM', $tokens, true);
                    $isSet = \in_array('SET', $tokens, true);
                    $isJson = \in_array('JSON', $tokens, true);
                    $isUnique = \in_array('UNIQUE', $tokens, true);
                    $uniqueColumns[$colName] = $isUnique;

                    if(\array_key_exists($colName, $data) && $data[$colName] !== null){
                        $val = $data[$colName];

                        if($isInt){
                            if(!\is_numeric($val)){
                                throw new PHPDBException("Column '$colName' expects INT value.");
                            }
                            $val = (int)$val;
                        } elseif($isBool){
                            if(\is_bool($val)){
                                $val = (bool)$val;
                            } elseif(\is_numeric($val)){
                                $val = ((int)$val) !== 0;
                            } elseif(\is_string($val)){
                                $v = strtolower(trim($val));
                                if($v === '1' || $v === 'true') $val = true;
                                elseif($v === '0' || $v === 'false') $val = false;
                                else throw new PHPDBException("Column '$colName' expects BOOLEAN value.");
                            } else {
                                throw new PHPDBException("Column '$colName' expects BOOLEAN value.");
                            }
                        } elseif($isFloat){
                            if(!\is_numeric($val)){
                                throw new PHPDBException("Column '$colName' expects FLOAT/DECIMAL value.");
                            }
                            $val = (float)$val;
                        } elseif($isDateTime || $isDate || $isTime || $isYear){
                            try {
                                $dt = $val instanceof \DateTime ? $val : new \DateTime((string)$val);
                            } catch (PHPDBException $e) {
                                // try with strtotime fallback
                                $ts = \strtotime((string)$val);
                                if($ts === false) {
                                    throw new PHPDBException("Column '$colName' expects a valid date/time value.");
                                }
                                $dt = new \DateTime("@$ts");
                                $dt->setTimezone(new \DateTimeZone(\date_default_timezone_get()));
                            }
                            if($isDate){
                                $val = $dt->format('Y-m-d');
                            } elseif($isTime){
                                $val = $dt->format('H:i:s');
                            } elseif($isYear){
                                $val = $dt->format('Y');
                            } else {
                                $val = $dt->format('Y-m-d H:i:s');
                            }
                        } elseif($isJson){
                            // ensure valid JSON string
                            if(!(\is_string($val) || \is_array($val) || \is_object($val))) {
                                throw new PHPDBException("Column '$colName' expects valid JSON data.");
                            }
                            if(!\is_string($val)) $val = json_encode($val);
                            if(json_last_error() !== JSON_ERROR_NONE) {
                                throw new PHPDBException("Column '$colName' contains invalid JSON data.");
                            }
                        } elseif($isEnum || $isSet){
                            // accept as string; further validation could parse enum/set values from definition
                            $val = (string)$val;
                        } else {
                            // text, blob, binary, varchar, etc.
                            $val = (string)$val;
                            // normalize text line endings when handling TEXT types
                            if($isText){
                                $val = preg_replace("/\r\n?/", "\n", $val);
                            }
                            // For BLOB/BINARY types, keep raw data (no charset conversion); for text types convert to DB charset
                            if(!$isBlob && !$isBinary){
                                // convert to database charset for textual data
                                $val = \mb_convert_encoding($val, $targetCharset, \mb_detect_encoding($val) ?: 'UTF-8');
                            }
                            if($isVarchar && $maxLen !== null && \mb_strlen($val) > $maxLen){
                                throw new PHPDBException("Column '$colName' exceeds maximum length of $maxLen characters.");
                            }
                        }
                        $row[$colName] = $val;
                    } else {
                        if($isAuto){
                            // compute next integer value
                            $max = 0;
                            foreach($table['rows'] as $existing){
                                if(isset($existing[$colName]) && \is_numeric($existing[$colName])){
                                    $max = max($max, (int)$existing[$colName]);
                                }
                            }
                            $row[$colName] = $max + 1;
                        } elseif($hasNotNull){
                            throw new PHPDBException("Column '$colName' is NOT NULL and no value was provided.");
                        } else {
                            $row[$colName] = null;
                        }
                    }
                }

                // enforce UNIQUE constraints
                foreach($uniqueColumns as $ucol => $isUniqueFlag){
                    if($isUniqueFlag && \array_key_exists($ucol, $row) && $row[$ucol] !== null){
                        foreach($table['rows'] as $existing){
                            if(\array_key_exists($ucol, $existing) && $existing[$ucol] == $row[$ucol]){
                                throw new PHPDBException("Column '$ucol' must be UNIQUE; duplicate value found.");
                            }
                        }
                    }
                }

                
            // Enforce foreign key constraints for INSERT
            $this->enforceForeignKeysOnInsert($dbKey, $tableName, $row);
$table['rows'][] = $row;
                $this->save($this->openDB);
            }else{
                throw new PHPDBException("Table '$tableName' does not exist in database '$this->openDB'.");
            }
        }
        else{
            throw new PHPDBException("Database '$this->openDB' does not exist.");
        }
    }
    /**
     * Updates data in the table
     * @param string $tableName Table name
     * @param array $data Data to update
     * @param string|array $conditions Conditions for update (SQL-like string e.g. "id=1 AND username='john'" or an array)
     * @throws PHPDBException Database or table does not exist.
     * @return void
     */
    
    public function update(string $tableName, array $data, string|array $conditions): void{
        $this->ensureCanWrite();
        if ($this->openDB === "") {
            throw new PHPDBException("Database '$this->openDB' is not open. Please open the database before updating data.");
        }

        $dbKey = strtolower($this->openDB);
        if (!isset($this->databases[$dbKey])) {
            throw new PHPDBException("Database '$this->openDB' does not exist.");
        }
        if (!isset($this->databases[$dbKey]['tables'][strtolower($tableName)])) {
            throw new PHPDBException("Table '$tableName' does not exist in database '$this->openDB'.");
        }

        $table = &$this->databases[$dbKey]['tables'][strtolower($tableName)];

        // ✅ STRICT: normalize to a canonical WHERE string (string input MUST start with WHERE)
        $where = $this->normalizeConditionsToWhereStrict($conditions);

        // ✅ evaluateCondition expects only the expression, not the WHERE keyword
        $condStr = ltrim(preg_replace('/^\s*WHERE\s+/i', '', $where));

        $matches = fn(array $row, string $cond): bool => $this->evaluateCondition($row, $cond);

        $updated = false;

        // Snapshot rows BEFORE update that match condition
        $preRows = [];
        foreach ($table['rows'] as $r0) {
            if ($matches($r0, $condStr)) { $preRows[] = $r0; }
        }

        foreach ($table['rows'] as $idx => $row) {
            if ($matches($row, $condStr)) {
                foreach ($data as $col => $val) {
                    $table['rows'][$idx][$col] = $val;
                }
                $updated = true;
            }
        }

        // Snapshot rows AFTER update that match condition
        $postRows = [];
        foreach ($table['rows'] as $r1) {
            if ($matches($r1, $condStr)) { $postRows[] = $r1; }
        }

        // Enforce foreign key constraints for UPDATE
        $this->enforceForeignKeysOnUpdate($dbKey, $tableName, $preRows, $postRows, $data, $condStr);

        if ($updated) {
            $this->save($this->openDB);
        }
    }

 
    /**
     * Deletes data from the table
     * @param string $tableName Table name
     * @param string|array $conditions Conditions for drop (SQL-like string e.g. "WHERE id=1 AND username='john'" or an array)
     * @return int Number of deleted rows
     */
    public function delete(string $tableName, string|array $conditions): int {
        $this->ensureCanDelete();

        if ($this->openDB === "") {
            throw new PHPDBException("Database '{$this->openDB}' is not open. Please open the database before deleting data.");
        }

        $dbKey = strtolower($this->openDB);
        if (!isset($this->databases[$dbKey])) {
            throw new PHPDBException("Database '{$this->openDB}' does not exist.");
        }
        if (!isset($this->databases[$dbKey]['tables'][strtolower($tableName)])) {
            throw new PHPDBException("Table '$tableName' does not exist in database '{$this->openDB}'.");
        }

        $table = &$this->databases[$dbKey]['tables'][strtolower($tableName)];

        // Normalize conditions to a canonical WHERE string (strict)
        $condStr = $this->normalizeConditionsToWhereStrict($conditions);

        // Strip leading WHERE for evaluateCondition
        $expr = ltrim(preg_replace('/^\s*WHERE\s+/i', '', $condStr));

        // closure to evaluate condition against a row
        $matches = fn(array $row, string $cond): bool => $this->evaluateCondition($row, $cond);

        $keptRows = [];
        $deletedCount = 0;

        foreach ($table['rows'] as $row) {
            if ($matches($row, $expr)) {
                $deletedCount++;
                // row is dropped
            } else {
                $keptRows[] = $row;
            }
        }

        if ($deletedCount > 0) {
            $table['rows'] = $keptRows;
            $this->save($this->openDB);
        }

        return $deletedCount;
    }

    /**
     * Converts string|array conditions into a canonical WHERE string.
     * Strict mode: string conditions MUST start with "WHERE".
     */
    private function normalizeConditionsToWhereStrict(string|array $conditions): string
    {
        if (is_array($conditions)) {
            // associative array => column => value pairs joined with AND
            $isAssoc = array_keys($conditions) !== range(0, count($conditions) - 1);

            if ($isAssoc) {
                $parts = [];
                foreach ($conditions as $k => $v) {
                    if (is_string($v)) {
                        // escape single quotes
                        $safe = str_replace("'", "\\'", $v);
                        $parts[] = "$k='$safe'";
                    } elseif ($v === null) {
                        $parts[] = "$k IS NULL";
                    } elseif (is_bool($v)) {
                        $parts[] = $k . ' ' . ($v ? '= TRUE' : '= FALSE');
                    } else {
                        // numbers or other scalar
                        $parts[] = "$k=$v";
                    }
                }
                $cond = implode(' AND ', $parts);
            } else {
                // numeric array of condition strings => join with AND
                $cond = implode(' AND ', $conditions);
            }

            $cond = trim($cond);
            if ($cond === '') {
                // Avoid mass delete by requiring some condition
                throw new PHPDBException("Empty conditions array provided. Refusing to delete without a WHERE expression.");
            }
            return 'WHERE ' . $cond;
        }

        // string input (strict WHERE required)
        $cond = trim($conditions);
        if ($cond === '') {
            throw new PHPDBException("Empty condition string provided. Refusing to delete without a WHERE clause.");
        }
        if (!preg_match('/^\s*WHERE\s+/i', $cond)) {
            throw new PHPDBException("Condition string must start with 'WHERE'. Provided: '$cond'");
        }

        return $cond;
    }



    
    /**
     * Fetches all rows from a specified table.
     *
     * Usage examples:
     *  - fetchAll('users')
     *  - fetchAll('users', "WHERE age >= 18")
     *  - fetchAll('users', "age >= 18 ORDER BY id DESC")
     *  - fetchAll('users', "ORDER BY created_at DESC")
     *
     * @param string $tableName Table name
     * @param ?string $condition Condition expression, optionally including:
     *        - optional leading "WHERE"
     *        - optional "ORDER BY <column> [ASC|DESC]"
     * @throws PHPDBException
     * @return array
     */
    public function fetchAll(string $tableName, ?string $condition = null): array{
        $this->ensureCanView(); 
        if ($this->openDB === '') {
            throw new PHPDBException("Database '{$this->openDB}' is not open. Please open the database before fetching data.");
        }

        $dbKey = strtolower($this->openDB);
        if (!isset($this->databases[$dbKey])) {
            throw new PHPDBException("Database '{$this->openDB}' does not exist.");
        }

        $tableKey = strtolower($tableName);
        if (!isset($this->databases[$dbKey]['tables'][$tableKey])) {
            throw new PHPDBException("Table '$tableName' does not exist in database '{$this->openDB}'.");
        }

        $rows = $this->databases[$dbKey]['tables'][$tableKey]['rows'];

        $condStr = trim((string)$condition);
        $order = null;

        if ($condStr !== '') {
            // Allow optional leading WHERE
            $condStr = preg_replace('/^\s*WHERE\s+/i', '', $condStr);

            // Extract ORDER BY from the condition string (if present)
            // Supports: ORDER BY col, ORDER BY col ASC, ORDER BY col DESC
            if (preg_match('/\bORDER\s+BY\s+([A-Za-z_][A-Za-z0-9_]*)\s*(ASC|DESC)?\b/i', $condStr, $m)) {
                $orderCol = $m[1];
                $orderDir = (isset($m[2]) && strtoupper($m[2]) === 'DESC') ? 'DESC' : 'ASC';
                $order = "$orderCol $orderDir";

                // Remove the ORDER BY clause from the condition expression before evaluating it
                $condStr = preg_replace('/\bORDER\s+BY\s+[A-Za-z_][A-Za-z0-9_]*\s*(ASC|DESC)?\b/i', '', $condStr);
                $condStr = trim($condStr);
            }
        }

        // Filter rows if condition expression exists
        if ($condStr !== '') {
            $rows = array_values(array_filter($rows, fn($r) => $this->evaluateCondition((array)$r, $condStr)));
        }

        // Apply ordering if requested via ORDER BY inside condition
        if ($order !== null && trim($order) !== '') {
            if (preg_match('/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(ASC|DESC)?\s*$/i', $order, $m)) {
                $orderColumn = $m[1];
                $orderDir = (isset($m[2]) && strtoupper($m[2]) === 'DESC') ? 'DESC' : 'ASC';

                usort($rows, function($a, $b) use ($orderColumn, $orderDir) {
                    $va = $a[$orderColumn] ?? null;
                    $vb = $b[$orderColumn] ?? null;

                    if ($va === $vb) return 0;
                    if ($va === null) return ($orderDir === 'ASC') ? -1 : 1;
                    if ($vb === null) return ($orderDir === 'ASC') ? 1 : -1;

                    // Date/time compare if both look like datetimes
                    $tsa = $this->toTimestampIfDateTime($va);
                    $tsb = $this->toTimestampIfDateTime($vb);
                    if ($tsa !== null && $tsb !== null) {
                        $cmp = $tsa <=> $tsb;
                        return ($orderDir === 'ASC') ? $cmp : -$cmp;
                    }

                    // Numeric compare
                    if (is_numeric($va) && is_numeric($vb)) {
                        $cmp = ((float)$va) <=> ((float)$vb);
                        return ($orderDir === 'ASC') ? $cmp : -$cmp;
                    }

                    // String compare fallback
                    $cmp = strcmp((string)$va, (string)$vb);
                    return ($orderDir === 'ASC') ? $cmp : -$cmp;
                });
            }
        }

        return $rows;
    }

    /**
     * Fetches a single row from a specified table based on conditions.
     * Supports optional ORDER BY <column> [ASC|DESC] in the conditions (similar to MySQL).
     * @param string $table Table name
     * @param string|array $conditions Conditions for fetch (SQL-like string e.g. "id=1 AND username='john' ORDER BY id DESC" or an array)
     * @return array|null An associative array representing the fetched row, or null if no matching row is found.
     */
    public function fetch(string $table, string|array $conditions): ?array{
        $this->ensureCanView();

        // Normalize conditions into a string and extract ORDER BY if present
        $condStr = is_array($conditions) ? implode(' AND ', $conditions) : (string)$conditions;
        $condStr = trim($condStr);

        $order = null;
        if ($condStr !== '') {
            // Allow optional leading WHERE
            $condStr = preg_replace('/^\s*WHERE\s+/i', '', $condStr);

            if (preg_match('/ORDER\s+BY\s+([A-Za-z_][A-Za-z0-9_]*)\s*(ASC|DESC)?/i', $condStr, $m)) {
                $orderCol = $m[1];
                $orderDir = (isset($m[2]) && strtoupper($m[2]) === 'DESC') ? 'DESC' : 'ASC';
                $order = "$orderCol $orderDir";
                $condStr = preg_replace('/ORDER\s+BY\s+[A-Za-z_][A-Za-z0-9_]*\s*(ASC|DESC)?/i', '', $condStr);
                $condStr = trim($condStr);
            }
        }
        $rows = $this->fetchAll($table, $condStr !== '' ? $condStr : null);
        if ($rows === []) return null;
        return [$rows[0]];
    }

    /**
     * Attempt best-effort crash recovery for a database file.
     *
     * This method is designed for scenarios where a crash happens during save(), leaving:
     * - a partially written main .phpdb file
     * - a leftover .tmp file
     * - or requiring rollback to a .bak or a timestamped *_backup_*.phpdb file.
     *
     * Requirements:
     * - Call Authorize() first so credentials are available for validation.
     *
     * @param string $name Database name or full path to a .phpdb file
     * @return bool True if the database file is valid or was successfully restored
     */
    public function crashRecovery(string $name): bool{
        // Require resolved credentials; Authorize may have been consumed by open() so accept fallbacks.
        if ($this->activeAccount === null) {
            if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) {
                PHPDBSecurity::auditLog("CrashRecovery blocked: missing credentials");
            }
            return false;
        }

        // Determine usable credentials: prefer one-time auth values, fall back to activeAccount username + in-memory passwordPlain.
        $credUser = $this->authUsername ?? ($this->activeAccount['username'] ?? null);
        $credPassword = $this->authPassword ?? $this->passwordPlain ?? null;
        if ($credUser === null || $credPassword === null) {
            if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) {
                PHPDBSecurity::auditLog("CrashRecovery blocked: missing credentials");
            }
            return false;
        }

        // Enforce view permission and db access policy.
        if (!(bool)($this->activeAccount['can_view'] ?? false)) return false;
        
        $input = trim($name);
        if ($input === '') return false;

        // If user provided a full path or a filename with .phpdb extension treat it as a path.
        $looksLikePath = is_file($input) || str_contains($input, DIRECTORY_SEPARATOR) || strtolower((string)pathinfo($input, PATHINFO_EXTENSION)) === 'phpdb';

        if ($looksLikePath) {
            // Ensure .phpdb extension if missing
            $filePathCandidate = strtolower((string)pathinfo($input, PATHINFO_EXTENSION)) === 'phpdb' ? $input : rtrim($input, DIRECTORY_SEPARATOR) . '.phpdb';

            // Preserve directory case but normalize the filename to lowercase
            $dir = dirname($filePathCandidate);
            $base = pathinfo($filePathCandidate, PATHINFO_FILENAME);
            $fileName = strtolower($base) . '.phpdb';
            $filePath = ($dir === '.' || $dir === '') ? $fileName : rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $fileName;

            // database key is the lowercased filename without extension
            $dbKey = strtolower($base);
        } else {
            // Treat as a DB name (case-insensitive names are stored lowercased)
            $dbKey = strtolower($input);

            // Enforce db-level access for named DBs
            if (!$this->accountCanAccessDb($this->activeAccount, $dbKey)) {
                return false;
            }

            $filePath = isset($this->databases[$dbKey])
                ? (rtrim($this->databases[$dbKey]['path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $dbKey . '.phpdb')
                : ("$dbKey.phpdb");
        }
        $tmpPath = "$filePath.tmp";
        $bakPath = "$filePath.bak";
        $dir = dirname($filePath);
        $stem = (string)pathinfo($filePath, PATHINFO_FILENAME);

       

        // Helper: best-effort audit
        $audit = function (string $msg): void {
            if (class_exists(__NAMESPACE__ . '\\PHPDBSecurity')) PHPDBSecurity::auditLog($msg);
        };
        
        // Step 1: If main file is valid, optionally cleanup stale tmp and return.
        if (is_file($filePath) && $this->validatePhpdbFile($filePath)) {
           
            if (is_file($tmpPath)) {
                @unlink($tmpPath);
            }
            $audit("CrashRecovery: main file already valid: $filePath");
            return true;
        }

        // Build candidate restore list (newest-first where applicable).
        $candidates = [];
        if (is_file($tmpPath)) $candidates[] = $tmpPath;
        if (is_file($bakPath)) $candidates[] = $bakPath;

        // Include timestamped backups created by backUpDatabase(): <name>_backup_YYYYmmdd_His.phpdb
        $pattern = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $stem . '_backup_*.phpdb';
        $backups = glob($pattern) ?: [];
        usort($backups, fn ($a, $b): int =>(@filemtime($b) ?: 0) <=> (@filemtime($a) ?: 0));
        foreach ($backups as $b) 
            if (is_file($b)) $candidates[] = $b;
        // Step 2: Try candidates until one validates.
        
        foreach ($candidates as $cand) {
            if (!$this->validatePhpdbFile($cand)) {
                continue;
            }
            
            // Preserve the corrupted main file (best-effort)
            if (is_file($filePath)) {
                $corrupt = $filePath . '.corrupt_' . date('Ymd_His');
                @rename($filePath, $corrupt);
            }
            // Restore candidate
            if ($cand === $tmpPath) {
                // Try atomic rename first
                if (!@rename($tmpPath, $filePath)) {
                    @copy($cand, $filePath);
                    @unlink($tmpPath);
                }
            } else {
                @copy($cand, $filePath);
            }

            // Final validation
            
            if (is_file($filePath) && $this->validatePhpdbFile($filePath)) {
                $audit("CrashRecovery: restored $filePath from $cand");
                return true;
            }
        }

        $audit("CrashRecovery failed: no valid recovery candidate for $filePath");
        return false;
    }

    /**
     * Validate that a .phpdb file can be decrypted and authenticated with current credentials.
     * This is used by crashRecovery() to pick a safe recovery candidate.
     */
    private function validatePhpdbFile(string $filePath): bool{
        // Allow using either the one-time authUsername/authPassword OR fall back to activeAccount username + in-memory passwordPlain.
        $credUser = $this->authUsername ?? ($this->activeAccount['username'] ?? null);
        $credPassword = $this->authPassword ?? $this->passwordPlain ?? null;
        if ($credUser === null || $credPassword === null) return false;

        $raw = @file_get_contents($filePath);
        if (!\is_string($raw) || trim($raw) === '') return false;
        $raw = trim($raw);
        // v2 format
        if (str_starts_with($raw, self::FILE_MAGIC_V2 . ':')) {
            $parts = explode(':', $raw, 5);
            if (\count($parts) !== 5) return false;
            [, $saltB64, $ivB64, $macB64, $cipherB64] = $parts;
            $salt = $this->b64urlDecode($saltB64);
            $iv = $this->b64urlDecode($ivB64);
            $mac = $this->b64urlDecode($macB64);
            $cipherRaw = $this->b64urlDecode($cipherB64);
            if ($salt === '' || $iv === '' || $mac === '' || $cipherRaw === '') return false;

            [$encKey, $macKey] = $this->deriveKeys($credPassword, $salt);
            $calc = hash_hmac('sha256', "$salt$iv$cipherRaw", $macKey, true);
            if (!PHPDBSecurity::timingSafeEquals($calc, $mac)) return false;
            $decrypted = openssl_decrypt($cipherRaw, $this->encryptionType, $encKey, OPENSSL_RAW_DATA, $iv);
            if ($decrypted === false || $decrypted === '') return false;
            $results = @unserialize($decrypted, ['allowed_classes' => false]);
            if (!\is_array($results) || !isset($results['username'], $results['password'], $results['name'])) return false;
            // Authenticate contents using resolved credentials
            $dummyHash = '$2y$12$C6UzMDM.H6dfI/f/IKcEeO9y3lGkz6tN8vD7ZrJmM5YpXz.3n/7QW';
            $storedUser = (string)$results['username'];
            $storedHash = (string)$results['password'];
            $userOk = PHPDBSecurity::timingSafeEquals($storedUser, $credUser);
            $passOk = $this->verifyPassword($credPassword, $userOk ? $storedHash : $dummyHash);
            return $userOk && $passOk;
        }

        // v1 legacy format
        $parts = explode('/', $raw, 2);
        if (\count($parts) != 2) return false;
        $key = $this->getSanitizedBase64($parts[0]);
        if (!\is_string($key) || $key === '') return false;
        $ivHex = substr($key, 0, 32);
        $iv = hex2bin($ivHex);
        if ($iv === false) return false;

        $decryptedData = openssl_decrypt($parts[1], $this->encryptionType, $key, 0, $iv);
        
        if ($decryptedData === false || $decryptedData === '') return false;
        $results = @unserialize($decryptedData, ['allowed_classes' => false]);
        if (!\is_array($results) || !isset($results['username'], $results['password'], $results['name'])) return false;

        $dummyHash = '$2y$12$C6UzMDM.H6dfI/f/IKcEeO9y3lGkz6tN8vD7ZrJmM5YpXz.3n/7QW';
        $storedUser = (string)$results['username'];
        $storedHash = (string)$results['password'];
        $userOk = PHPDBSecurity::timingSafeEquals($storedUser, $credUser);
        $passOk = $this->verifyPassword($credPassword, $userOk ? $storedHash : $dummyHash);
        return $userOk && $passOk;
    }

    /**
     * Destroy the class object
     */
    public function __destruct(){
        if($this->openDB !== ''){
            $this->close($this->openDB);
        }
    }

    private function parseForeignKeyDef(string $localCol, string $def): ?array {
        $re = '/REFERENCES\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/i';
        if (!preg_match($re, $def, $m)) return null;
        $fk = [
            'local_col' => $localCol,
            'ref_table' => strtolower($m[1]),
            'ref_col'   => $m[2],
            'on_delete' => null,
            'on_update' => null,
        ];
        if (preg_match('/ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $dm)) {
            $fk['on_delete'] = strtoupper(str_replace('  ', ' ', $dm[1]));
        }
        if (preg_match('/ON\s+UPDATE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $um)) {
            $fk['on_update'] = strtoupper(str_replace('  ', ' ', $um[1]));
        }
        return $fk;
    }
    private function getTableForeignKeys(string $dbKey, string $tableName): array {
        $tableKey = strtolower($tableName);
        $fks = [];
        if (!isset($this->databases[$dbKey]['tables'][$tableKey])) return $fks;
        $cols = (array)($this->databases[$dbKey]['tables'][$tableKey]['columns'] ?? []);
        foreach ($cols as $col => $def) {
            $fk = $this->parseForeignKeyDef((string)$col, (string)$def);
            if ($fk !== null) $fks[] = $fk;
        }
        return $fks;
    }
    private function getChildConstraintsReferencing(string $dbKey, string $parentTable): array {
        $parentKey = strtolower($parentTable);
        $out = [];
        $tables = (array)($this->databases[$dbKey]['tables'] ?? []);
        foreach ($tables as $tKey => $tDef) {
            $cols = (array)($tDef['columns'] ?? []);
            foreach ($cols as $col => $def) {
                $fk = $this->parseForeignKeyDef((string)$col, (string)$def);
                if ($fk !== null && strtolower($fk['ref_table']) === $parentKey) {
                    $fk['local_table'] = (string)$tDef['name'];
                    $out[] = $fk;
                }
            }
        }
        return $out;
    }
    private function enforceForeignKeysOnInsert(string $dbKey, string $tableName, array $row): void {
        $fks = $this->getTableForeignKeys($dbKey, $tableName);
        foreach ($fks as $fk) {
            $val = $row[$fk['local_col']] ?? null;
            if ($val === null) continue;
            $parentKey = strtolower($fk['ref_table']);
            if (!isset($this->databases[$dbKey]['tables'][$parentKey])) {
                throw new PHPDBException("Foreign key references unknown parent table '{$fk['ref_table']}'.");
            }
            $parentRows = (array)$this->databases[$dbKey]['tables'][$parentKey]['rows'];
            $found = false;
            foreach ($parentRows as $pr) {
                if (($pr[$fk['ref_col']] ?? null) == $val) { $found = true; break; }
            }
            if (!$found) {
                throw new PHPDBException("Foreign key constraint failed on '{$tableName}.{$fk['local_col']}' referencing '{$fk['ref_table']}.{$fk['ref_col']}' – parent value not found.");
            }
        }
    }
    private function enforceForeignKeysOnUpdate(string $dbKey, string $tableName, array $preRows, array $postRows, array $data, string $condStr): void {
        $tKey = strtolower($tableName);
        $localFks = $this->getTableForeignKeys($dbKey, $tableName);
        if ($localFks !== []) {
            foreach ($postRows as $idx => $row) {
                $affected = false;
                foreach ($data as $col => $_) { if (array_key_exists($col, $row)) { $affected = true; break; } }
                if (!$affected) continue;
                foreach ($localFks as $fk) {
                    if (!array_key_exists($fk['local_col'], $data)) continue;
                    $newVal = $row[$fk['local_col']] ?? null;
                    if ($newVal === null) continue;
                    $parentKey = strtolower($fk['ref_table']);
                    $parentRows = (array)($this->databases[$dbKey]['tables'][$parentKey]['rows'] ?? []);
                    $found = false;
                    foreach ($parentRows as $pr) { if (($pr[$fk['ref_col']] ?? null) == $newVal) { $found = true; break; } }
                    if (!$found) {
                        throw new PHPDBException("Foreign key constraint failed on UPDATE: '{$tableName}.{$fk['local_col']}' now references non-existent '{$fk['ref_table']}.{$fk['ref_col']}'.");
                    }
                }
            }
        }
        $childConstraints = $this->getChildConstraintsReferencing($dbKey, $tableName);
        if ($childConstraints === []) return;
        $changedPairs = [];
        $changedCols = array_keys($data);
        foreach ($preRows as $i => $oldRow) {
            $newRow = $postRows[$i] ?? $oldRow;
            foreach ($changedCols as $c) {
                $ov = $oldRow[$c] ?? null; $nv = $newRow[$c] ?? $ov;
                if ($ov !== $nv) { $changedPairs[] = [$c, $ov, $nv]; }
            }
        }
        if ($changedPairs === []) return;
        foreach ($childConstraints as $con) {
            foreach ($changedPairs as $pair) {
                $refCol = $pair[0]; $oldVal = $pair[1]; $newVal = $pair[2];
                if ($con['ref_col'] !== $refCol) continue;
                $childKey = strtolower($con['local_table']);
                $rows = (array)($this->databases[$dbKey]['tables'][$childKey]['rows'] ?? []);
                $action = (string)($con['on_update'] ?? 'RESTRICT');
                if ($action === 'RESTRICT') {
                    foreach ($rows as $r) {
                        if (($r[$con['local_col']] ?? null) == $oldVal && $oldVal != $newVal) {
                            $this->databases[$dbKey]['tables'][$tKey]['rows'] = $preRows;
                            throw new PHPDBException("ON UPDATE RESTRICT: '{$tableName}.{$refCol}' change blocked due to dependent rows in '{$con['local_table']}'.");
                        }
                    }
                } elseif ($action === 'SET NULL') {
                    foreach ($rows as $ri => $r) {
                        if (($r[$con['local_col']] ?? null) == $oldVal && $oldVal != $newVal) {
                            $this->databases[$dbKey]['tables'][$childKey]['rows'][$ri][$con['local_col']] = null;
                        }
                    }
                } else { // CASCADE
                    foreach ($rows as $ri => $r) {
                        if (($r[$con['local_col']] ?? null) == $oldVal && $oldVal != $newVal) {
                            $this->databases[$dbKey]['tables'][$childKey]['rows'][$ri][$con['local_col']] = $newVal;
                        }
                    }
                }
            }
        }
    }
    private function applyParentOnDeleteActions(string $dbKey, string $parentTable, array $toDeleteRows): void {
        $childConstraints = $this->getChildConstraintsReferencing($dbKey, $parentTable);
        if ($childConstraints === []) return;
        foreach ($childConstraints as $con) {
            $childKey = strtolower($con['local_table']);
            $action = (string)($con['on_delete'] ?? 'RESTRICT');
            $rows = (array)($this->databases[$dbKey]['tables'][$childKey]['rows'] ?? []);
            if ($action === 'RESTRICT') {
                foreach ($toDeleteRows as $pRow) {
                    $pVal = $pRow[$con['ref_col']] ?? null;
                    if ($pVal === null) continue;
                    foreach ($rows as $r) {
                        if (($r[$con['local_col']] ?? null) == $pVal) {
                            throw new PHPDBException("ON DELETE RESTRICT: cannot delete from '{$parentTable}' while '{$childKey}' references value '{$pVal}'.");
                        }
                    }
                }
            } elseif ($action === 'SET NULL') {
                foreach ($rows as $ri => $r) {
                    foreach ($toDeleteRows as $pRow) {
                        $pVal = $pRow[$con['ref_col']] ?? null;
                        if ($pVal === null) continue;
                        if (($r[$con['local_col']] ?? null) == $pVal) {
                            $this->databases[$dbKey]['tables'][$childKey]['rows'][$ri][$con['local_col']] = null;
                            break;
                        }
                    }
                }
            } else { // CASCADE
                $newRows = [];
                foreach ($rows as $r) {
                    $keep = true;
                    foreach ($toDeleteRows as $pRow) {
                        $pVal = $pRow[$con['ref_col']] ?? null;
                        if (($r[$con['local_col']] ?? null) == $pVal) { $keep = false; break; }
                    }
                    if ($keep) { $newRows[] = $r; }
                }
                $this->databases[$dbKey]['tables'][$childKey]['rows'] = $newRows;
            }
        }
    }
}

class PHPDBUtils{
    /**
     * PHPDB Utilities
     */
    public function __construct(){
        # nothing to do here
    }
    /**
     * Find a term in a column
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $columnName Column name
     * @param string $searchTerm Search term
     * @param ?callable $output Optional callback for results
     * @return ?array Results array
     */
    public static function find(PHPDB $PHPDB, string $tableName, string $columnName, string $searchTerm, ?callable $output=null): ?array{
        $results = [];
        $allRows = $PHPDB->fetchAll($tableName);
        foreach($allRows as $row){
            if(isset($row[$columnName]) && stripos((string)$row[$columnName], $searchTerm) !== false){
                $results[] = $row;
            }
        }
        if($output !== null) {
            $output($results);
            return null;
        }
        else return $results;
    }
    /**
     * Searches the table for a term in all columns
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $searchTerm Search term
     * @return bool True if found, false otherwise
     */
    public static function search(PHPDB $PHPDB, string $tableName, string $searchTerm): bool{
        $allRows = $PHPDB->fetchAll($tableName);
        foreach($allRows as $row){
            foreach($row as $colValue){
                if(stripos((string)$colValue, $searchTerm) !== false){
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Sort the data
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $orderColumn Order column
     * @param string $orderDir Order direction (ASC|DESC)
     * @return array Sorted array
     */
    public static function sort(PHPDB $PHPDB, string $tableName, string $orderColumn, string $orderDir='ASC'): array{
        $rows = $PHPDB->fetchAll($tableName);
        usort($rows, function($a, $b) use ($orderColumn, $orderDir) {
            $va = $a[$orderColumn] ?? null;
            $vb = $b[$orderColumn] ?? null;

            if ($va === $vb) return 0;
            if ($va === null) return ($orderDir === 'ASC') ? -1 : 1;
            if ($vb === null) return ($orderDir === 'ASC') ? 1 : -1;

            $cmp = \is_numeric($va) && \is_numeric($vb) ? ($va + 0) <=> ($vb + 0) : strcmp((string)$va, (string)$vb);
            return ($orderDir === 'ASC') ? $cmp : -$cmp;
        });
        return $rows;
    }
    /**
     * Count the number of rows in a table
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @return int Number of rows
     */
    public static function countRows(PHPDB $PHPDB, string $tableName): int{
        $rows = $PHPDB->fetchAll($tableName);
        return \count($rows);
    }
    /**
     * Filter rows based on a callback
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param callable $callback Callback function to filter rows. Example: function($row) { return $row['column'] > 10; }
     * @return array Filtered array
     */
    public static function filter(PHPDB $PHPDB, string $tableName, callable $callback): array{
        $rows = $PHPDB->fetchAll($tableName);
        return array_filter($rows, $callback);
    }
    /**
     * Create an index to a column
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $columnName Column name
     * @return void
     */
    public static function createIndex(PHPDB $PHPDB, string $tableName, string $columnName): void{
        $rows = $PHPDB->fetchAll($tableName);
        $index = [];
        foreach($rows as $row){
            if(isset($row[$columnName])){
                $key = (string)$row[$columnName];
                if(!isset($index[$key])){
                    $index[$key] = [];
                }
                $index[$key][] = $row;
            }
        }
        // Store index as a special table
        $indexTableName = "$tableName._index_.$columnName";
        try {
            $PHPDB->createTable($indexTableName, ['value'=>'VARCHAR(255)', 'rows'=>'TEXT']);
        } catch(PHPDBException $e){
            // Table may already exist; ignore
        }
        foreach($index as $val => $rowsArr){
            $PHPDB->insert($indexTableName, [
                'value' => $val,
                'rows' => serialize($rowsArr)
            ]);
        }
    }
    /**
     * Update an index to a column
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $columnName Column name
     * @return void
     */
    public static function updateIndex(PHPDB $PHPDB, string $tableName, string $columnName): void{
        $indexTableName = "$tableName._index_.$columnName";
        try {
            $PHPDB->dropTable($indexTableName);
        } catch(PHPDBException $e){
            // ignore
        }
        PHPDBUtils::createIndex($PHPDB, $tableName, $columnName);
    }
    /**
     * Drop the index
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @param string $columnName Column name
     * @return void
     */
    public static function dropIndex(PHPDB $PHPDB, string $tableName, string $columnName): void{
        $indexTableName = "$tableName._index_.$columnName";
        try {
            $PHPDB->dropTable($indexTableName);
        } catch(PHPDBException $e){
            // ignore
        }
    }
    /**
     * List indexes of a table
     * @param PHPDB $PHPDB PHPDB instance
     * @param string $tableName Table Name
     * @return array Array of index column names
     */
    public static function listIndexes(PHPDB $PHPDB, string $tableName): array{
        $allTables = $PHPDB->listTables();
        $indexes = [];
        foreach($allTables as $tbl){
            if(preg_match('/^' . preg_quote($tableName, '/') . '\._index_\.(.+)$/', $tbl, $m)){
                $indexes[] = $m[1];
            }
        }
        return $indexes;
    }
    
    /**
     * Builds a SQL-like condition string from an associative array.
     * - Keys are treated as column identifiers and quoted with backticks.
     * - Values are mapped to SQL literals with reasonable formatting.
     * - Arrays produce IN() or a combined (IS NULL OR IN (...)) when NULL is present.
     *
     * Examples:
     *  ['id' => 1, 'name' => "O'Hara", 'active' => true]
     *    => "`id`=1 AND `name`='O''Hara' AND `active` = TRUE"
     *
     *  ['id' => [1,2,3], 'status' => [null, 'active']]
     *    => "`id` IN (1,2,3) AND (`status` IS NULL OR `status` IN ('active'))"
     */
    public static function conditionBuilder(array $conditions): string{
        $parts = [];

        foreach ($conditions as $key => $value) {
            // Quote the identifier with backticks; allow dotted names: table.column
            $identifier = implode('.', array_map(
                fn($p) => '`' . str_replace('`', '``', (string)$p) . '`',
                explode('.', (string)$key)
            ));

            // Handle arrays => IN / IS NULL
            if (\is_array($value)) {
                // Normalize array values to literals
                $literals = [];
                $hasNull = false;

                foreach ($value as $v) {
                    if ($v === null) {
                        $hasNull = true;
                        continue;
                    }
                    $literals[] = self::toSqlLiteral($v);
                }

                if ($hasNull && \count($literals) > 0) {
                    // (col IS NULL OR col IN (...))
                    $parts[] = \sprintf(
                        '( %s IS NULL OR %s IN (%s) )',
                        $identifier,
                        $identifier,
                        implode(',', $literals)
                    );
                } elseif ($hasNull && \count($literals) === 0) {
                    // Only NULLs in the array -> col IS NULL
                    $parts[] = \sprintf('%s IS NULL', $identifier);
                } elseif (!$hasNull && \count($literals) > 0) {
                    // Regular IN list
                    $parts[] = \sprintf('%s IN (%s)', $identifier, implode(',', $literals));
                } else {
                    // Empty array -> no possible match
                    $parts[] = 'FALSE';
                }

                continue;
            }

            // Scalars and nulls
            if ($value === null) {
                $parts[] = \sprintf('%s IS NULL', $identifier);
            } elseif (\is_bool($value)) {
                $parts[] = $identifier . ' ' . ($value ? '= TRUE' : '= FALSE');
            } else {
                $parts[] = \sprintf('%s=%s', $identifier, self::toSqlLiteral($value));
            }
        }
        return implode(' AND ', $parts);
    }

    /**
     * Convert a PHP value to a SQL literal string suitable for conditionBuilder.
     * - Numbers: as-is
     * - Strings: single quoted, with internal single quotes doubled
     * - DateTimeInterface: 'Y-m-d H:i:s'
     * - Objects with __toString(): stringified then quoted
     */
    private static function toSqlLiteral($v): string
    {
        if (is_int($v) || is_float($v)) {
            return (string)$v;
        }
        if ($v instanceof \DateTimeInterface) {
            return "'" . $v->format('Y-m-d H:i:s') . "'";
        }
        if (is_string($v)) {
            // SQL-standard string escaping by doubling single quotes
            $safe = str_replace("'", "''", $v);
            return "'" . $safe . "'";
        }
        if (is_bool($v)) {
            return $v ? 'TRUE' : 'FALSE';
        }
        if (is_object($v) && method_exists($v, '__toString')) {
            $s = (string)$v;
            $safe = str_replace("'", "''", $s);
            return "'" . $safe . "'";
        }

        // Fallback: JSON-encode arrays/objects; other scalars stringified
        // (Should not hit for arrays because conditionBuilder handles them separately)
        if (is_array($v) || is_object($v)) {
            $json = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $safe = str_replace("'", "''", (string)$json);
            return "'" . $safe . "'";
        }

        // Default stringification
        $safe = str_replace("'", "''", (string)$v);
        return "'" . $safe . "'";
    }

    /**
     * Export data to JSON format
     * @param array $data Data array
     * @return string JSON string
     */
    public static function exportToJSON(array $data): string{
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    /**
     * Export as SQL
     * @param array $data Data array
     * @return string SQL string
     */
    public static function exportToSQL(array $data): string{
        $tables  = isset($data['tables']) && is_array($data['tables']) ? $data['tables'] : [];
        $dbName  = (string)($data['name'] ?? 'phpdb');
        $charset = (string)($data['charset'] ?? '');
        $collate = (string)($data['collation'] ?? '');

        // Normalize MySQL charset + collation (prefer utf8mb4)
        [$charset, $collate] = self::normalizeMySQLCharsetCollation($charset, $collate);

        $out  = "-- PHPDB SQL Export
";
        $out .= "-- Database: {$dbName}
";
        $out .= "-- Charset:  {$charset}
";
        $out .= "-- Collation: {$collate}

";

        foreach ($tables as $tableName => $table) {
            if (!is_array($table)) continue;
            $columns = isset($table['columns']) && is_array($table['columns']) ? $table['columns'] : [];
            $rows    = isset($table['rows']) && is_array($table['rows']) ? $table['rows'] : [];
            if ($columns === []) continue;

            $out .= "DROP TABLE IF EXISTS `{$tableName}`;
";
            $out .= "CREATE TABLE `{$tableName}` (
";

            $defs = [];
            $fks  = [];

            foreach ($columns as $col => $type) {
                $def = (string)$type;

                // Detect column-level REFERENCES clause and capture actions
                if (preg_match('/REFERENCES\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/i', $def, $m)) {
                    $refTable  = $m[1];
                    $refColumn = $m[2];
                    $onDelete  = null;
                    $onUpdate  = null;
                    if (preg_match('/ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $dm)) $onDelete = strtoupper($dm[1]);
                    if (preg_match('/ON\s+UPDATE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $um)) $onUpdate = strtoupper($um[1]);
                    $fks[] = [
                        'col' => (string)$col,
                        'ref_table' => $refTable,
                        'ref_col' => $refColumn,
                        'on_delete' => $onDelete,
                        'on_update' => $onUpdate,
                    ];

                    // Strip embedded REFERENCES from column definition
                    $def = preg_replace('/\s+REFERENCES\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*(ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL))?\s*(ON\s+UPDATE\s+(CASCADE|RESTRICT|SET\s+NULL))?/i', '', $def);
                    $def = trim($def);
                }

                $defs[] = "  `{$col}` {$def}";
            }

            foreach ($fks as $fk) {
                $constraintName = 'fk_' . preg_replace('/[^A-Za-z0-9_]+/', '_', $tableName . '_' . $fk['col']);
                $line = "  CONSTRAINT `{$constraintName}` FOREIGN KEY (`{$fk['col']}`) REFERENCES `{$fk['ref_table']}`(`{$fk['ref_col']}`)";
                if (!empty($fk['on_delete'])) $line .= " ON DELETE {$fk['on_delete']}";
                if (!empty($fk['on_update'])) $line .= " ON UPDATE {$fk['on_update']}";
                $defs[] = $line;
            }

            $out .= implode(",
", $defs) . "
) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collate};

";

            if ($rows !== []) {
                $colList = array_keys($columns);
                foreach ($rows as $row) {
                    $vals = [];
                    foreach ($colList as $col) {
                        $val = $row[$col] ?? null;
                        if ($val === null) {
                            $vals[] = 'NULL';
                        } else {
                            if (is_array($val) || is_object($val)) {
                                $val = json_encode($val, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
                            }
                            $val = str_replace("'", "''", (string)$val);
                            $vals[] = "'{$val}'";
                        }
                    }
                    $out .= "INSERT INTO `{$tableName}` (`" . implode("`,`", $colList) . "`) VALUES (" . implode(", ", $vals) . ");
";
                }
                $out .= "
";
            }
        }

        return trim($out);
    }

    /** Normalize MySQL charset + collation to valid pairs. */
    private static function normalizeMySQLCharsetCollation(string $charset, string $collate): array
    {
        // Accept common inputs; coerce to valid MySQL names.
        $c = strtolower(trim($charset));
        // Treat hyphenated "utf-8"/"utf8" as utf8mb4 (recommended)
        if ($c === '' || $c === 'utf-8' || $c === 'utf8' || $c === 'utf8mb3') {
            $c = 'utf8mb4'; // MySQL recommends utf8mb4 as the UTF-8 implementation. [1](https://dev.mysql.com/doc/refman/8.4/en/charset.html)
        }

        // Choose a safe default collation for the charset if not matching/omitted
        $col = strtolower(trim($collate));
        $pairs = [
            'utf8mb4' => ['utf8mb4_0900_ai_ci', 'utf8mb4_unicode_ci', 'utf8mb4_general_ci'],
            'utf8'    => ['utf8_general_ci', 'utf8_unicode_ci'], // if someone truly wants utf8mb3/utf8. [2](https://docs.oracle.com/cd/E17952_01/mysql-8.0-en/charset-mysql.html)
            'latin1'  => ['latin1_swedish_ci'],
        ];

        if (!isset($pairs[$c])) {
            // Fallback for unknown charsets: use utf8mb4
            $c = 'utf8mb4';
        }

        // If provided collation doesn't start with the charset, select the first known default
        $valids = $pairs[$c];
        $colOk = $col !== '' && str_starts_with($col, $c);
        if (!$colOk) {
            $col = $valids[0]; // prefer utf8mb4_0900_ai_ci on MySQL 8+; else unicode_ci/general_ci also valid. [1](https://dev.mysql.com/doc/refman/8.4/en/charset.html)
        }

        return [$c, $col];
    }


    /**
     * Export to CSV
     * @param array $data Data array
     * @return string CSV string
     */
    public static function exportToCSV(array $data): string{
        $tables = isset($data['tables']) && \is_array($data['tables']) ? $data['tables'] : [];
        $dbName = (string)($data['name'] ?? 'phpdb');

        $out  = "# PHPDB CSV Export\n";
        $out .= "# Database: {$dbName}\n\n";

        foreach ($tables as $tableName => $table) {
            if (!\is_array($table)) continue;

            $columns = isset($table['columns']) && \is_array($table['columns']) ? $table['columns'] : [];
            $rows    = isset($table['rows'])    && \is_array($table['rows'])    ? $table['rows']    : [];
            if ($columns === []) continue;

            $colList = array_keys($columns);

            // Section header
            $out .= "# Table: {$tableName}\n";

            // Header row (quote for consistency)
            $out .= implode(',', array_map(fn($c) => self::csvField($c, /*trimOuterQuotes*/ false), $colList)) . "\n";

            // Data rows in column order
            foreach ($rows as $row) {
                $fields = [];
                foreach ($colList as $col) {
                    $val = $row[$col] ?? '';
                    $fields[] = self::csvField(self::stringifyValue($val), /*trimOuterQuotes*/ true);
                }
                $out .= implode(',', $fields) . "\n";
            }

            $out .= "\n";
        }

        return trim($out);
    }

    // --- HELPERS (add these inside PHPDBUtils as private static) ---
    private static function stringifyValue($val): string{
        if ($val === null) return '';
        if (\is_array($val) || \is_object($val)) {
            $json = json_encode($val, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            return $json !== false ? $json : '';
        }
        return (string)$val;
    }

    /**
     * Convert a raw value to a CSV-safe field:
     *  - optionally remove one redundant outer pair of quotes (if present),
     *  - quote only when the field contains a quote, comma, or newline,
     *  - escape embedded quotes by doubling them.
     */
    private static function csvField(string $s, bool $trimOuterQuotes = true): string{
        $s = trim($s);

        // If the entire value looks like it was pre-quoted (e.g., "john_doe"),
        // and there are no extra quotes inside, strip the outer quotes once.
        if ($trimOuterQuotes && \strlen($s) >= 2 && $s[0] === '"' && substr($s, -1) === '"') {
            $inner = substr($s, 1, -1);
            // Only strip if there are no additional quotes inside (heuristic to avoid altering legit content like: He said "Hi")
            if (strpos($inner, '"') === false) {
                $s = $inner;
            }
        }

        // Decide if quoting is needed (RFC-4180): quote if field contains quote, comma, or CR/LF
        $needsQuote = (strpbrk($s, "\",\r\n") !== false);
        if ($needsQuote) {
            $s = '"' . str_replace('"', '""', $s) . '"';
        }
        return $s;
    }


    /**
     * Export data as SQLite
     * @param array $data Data array
     * @return string SQLite string
     */
    public static function exportToSQLite(array $data): string{
        $tables = isset($data['tables']) && is_array($data['tables']) ? $data['tables'] : [];
        $dbName = (string)($data['name'] ?? 'phpdb');

        $out  = "-- PHPDB SQLite Export
";
        $out .= "-- Database: {$dbName}

";
        $out .= "BEGIN TRANSACTION;

";

        foreach ($tables as $tableName => $table) {
            if (!is_array($table)) continue;
            $columns = isset($table['columns']) && is_array($table['columns']) ? $table['columns'] : [];
            $rows    = isset($table['rows']) && is_array($table['rows']) ? $table['rows'] : [];
            if ($columns === []) continue;

            $defs = [];
            $fks  = [];

            foreach ($columns as $col => $type) {
                $def = (string)$type;

                if (preg_match('/REFERENCES\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/i', $def, $m)) {
                    $refTable  = $m[1];
                    $refColumn = $m[2];
                    $onDelete = null; $onUpdate = null;
                    if (preg_match('/ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $dm)) $onDelete = strtoupper($dm[1]);
                    if (preg_match('/ON\s+UPDATE\s+(CASCADE|RESTRICT|SET\s+NULL)/i', $def, $um)) $onUpdate = strtoupper($um[1]);
                    $fks[] = [
                        'col' => (string)$col,
                        'ref_table' => $refTable,
                        'ref_col' => $refColumn,
                        'on_delete' => $onDelete,
                        'on_update' => $onUpdate,
                    ];

                    $def = preg_replace('/\s+REFERENCES\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*(ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL))?\s*(ON\s+UPDATE\s+(CASCADE|RESTRICT|SET\s+NULL))?/i', '', $def);
                    $def = trim($def);
                }

                $cleanDef = self::translateToSQLiteType($def);
                $defs[] = '  "' . $col . '" ' . $cleanDef;
            }

            foreach ($fks as $fk) {
                $line = '  FOREIGN KEY ("' . $fk['col'] . '") REFERENCES "' . $fk['ref_table'] . '"("' . $fk['ref_col'] . '")';
                if (!empty($fk['on_delete'])) $line .= ' ON DELETE ' . $fk['on_delete'];
                if (!empty($fk['on_update'])) $line .= ' ON UPDATE ' . $fk['on_update'];
                $defs[] = $line;
            }

            $out .= 'DROP TABLE IF EXISTS "' . $tableName . '";
';
            $out .= 'CREATE TABLE "' . $tableName . '" (
' . implode(",
", $defs) . "
);

";

            if ($rows !== []) {
                $colList = array_keys($columns);
                foreach ($rows as $row) {
                    $vals = [];
                    foreach ($colList as $col) {
                        $val = $row[$col] ?? null;
                        if ($val === null) {
                            $vals[] = 'NULL';
                        } else {
                            if (is_array($val) || is_object($val)) {
                                $val = json_encode($val, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
                            }
                            $val = str_replace("'", "''", (string)$val);
                            $vals[] = "'{$val}'";
                        }
                    }
                    $out .= 'INSERT INTO "' . $tableName . '" ("' . implode('","', $colList) . '") VALUES (' . implode(', ', $vals) . ");
";
                }
                $out .= "
";
            }
        }

        $out .= "COMMIT;
";
        return trim($out);
    }

        /** Map common MySQL column definitions to SQLite-friendly forms and fix AUTOINCREMENT spelling/placement. */
        private static function translateToSQLiteType(string $mysqlType): string{
            $t = strtoupper($mysqlType);

            // If this column is any integer type with AUTO_INCREMENT, force SQLite's exact form:
            // INTEGER PRIMARY KEY AUTOINCREMENT
            if (str_contains($t, 'AUTO_INCREMENT')) {
                // Ensure AUTOINCREMENT spelling and INTEGER PRIMARY KEY placement
                return 'INTEGER PRIMARY KEY AUTOINCREMENT'; // exact syntax required by SQLite. [3](https://sqlite.org/autoinc.html)
            }

            // Broad type mappings (SQLite is typeless but uses affinities)
            // Integer-like
            if (preg_match('/\b(TINYINT|SMALLINT|MEDIUMINT|INT|BIGINT)\b/', $t)) {
                // For BOOL/BOOLEAN, prefer INTEGER affinity (0/1)
                if (preg_match('/\b(BOOL|BOOLEAN)\b/', $t)) return 'INTEGER';
                return 'INTEGER';
            }

            // Floating-point / numeric
            if (preg_match('/\b(FLOAT|DOUBLE|REAL|DECIMAL|NUMERIC)\b/', $t)) {
                return 'REAL';
            }

            // Temporal → store as TEXT (ISO 8601)
            if (preg_match('/\b(DATE|DATETIME|TIMESTAMP|TIME|YEAR)\b/', $t)) {
                return 'TEXT';
            }

            // Character / text / JSON
            if (preg_match('/\b(CHAR|VARCHAR|TEXT|TINYTEXT|MEDIUMTEXT|LONGTEXT|JSON)\b/', $t)) {
                return 'TEXT';
            }

            // Binary blobs
            if (preg_match('/\b(BLOB|TINYBLOB|MEDIUMBLOB|LONGBLOB|BINARY|VARBINARY)\b/', $t)) {
                return 'BLOB';
            }

            // Fallback: keep as TEXT
            return 'TEXT';
        }


        
// ------------------ IMPORTERS ------------------

    /**
     * Import from a PHPDB JSON export or an array-of-objects JSON.
     */
    public static function importFromJSON(string $raw, string $fallbackName): array{
        $data = json_decode($raw, true);
        if (!\is_array($data)) throw new PHPDBException("Invalid JSON content.");

        // Already a PHPDB export structure
        if (isset($data['tables']) && \is_array($data['tables'])) {
            $dbName   = isset($data['name']) ? (string)$data['name'] : $fallbackName;
            $charset  = isset($data['charset']) ? (string)$data['charset'] : 'utf-8';
            $collate  = isset($data['collation']) ? (string)$data['collation'] : 'utf8_general_ci';
            $tables   = [];

            foreach ($data['tables'] as $tname => $tdef) {
                $columns = isset($tdef['columns']) && \is_array($tdef['columns']) ? $tdef['columns'] : [];
                $rows    = isset($tdef['rows'])    && \is_array($tdef['rows'])    ? $tdef['rows']    : [];

                // Infer columns if missing
                if ($columns === [] && $rows !== [] && \is_array($rows[0] ?? null)) {
                    foreach (array_keys($rows[0]) as $c) $columns[$c] = 'TEXT';
                }
                self::finalizeTable($tables, (string)$tname, $columns, $rows);
            }

            return [
                'name'      => $dbName,
                'charset'   => $charset,
                'collation' => $collate,
                'tables'    => $tables
            ];
        }

        // Treat as a single table array-of-objects
        if (!isset($data[0]) || !\is_array($data[0])) 
            throw new PHPDBException("Unsupported JSON shape for import.");
        $columns = [];
        foreach (array_keys($data[0]) as $c) $columns[$c] = 'TEXT';

        $tables = [];
        self::finalizeTable($tables, 'import', $columns, $data);

        return [
            'name'      => $fallbackName,
            'charset'   => 'utf-8',
            'collation' => 'utf8_general_ci',
            'tables'    => $tables
        ];
    }

    /**
     * Import from the CSV format produced by exportToCSV().
     */
    public static function importFromCSV(string $raw, string $fallbackName): array{
        $lines = preg_split("/\r\n|\n|\r/", $raw);
        $dbName = $fallbackName;
        $currentTable = '';
        $headers = [];
        $rows    = [];
        $tables  = [];

        foreach ($lines as $line) {
            $trim = trim($line);
            if ($trim === '') continue;

            if (str_starts_with($trim, '#')) {
                if (preg_match('/^#\s*Database:\s*(.+)\s*$/i', $trim, $m)) {
                    $dbName = trim($m[1]);
                } elseif (preg_match('/^#\s*Table:\s*(.+)\s*$/i', $trim, $m)) {
                    // finalize previous table
                    if ($currentTable !== '') {
                        self::finalizeTable($tables, $currentTable, array_map(
                            fn($h) => ['name' => $h, 'def' => 'TEXT'], $headers
                        ), $rows);
                    }
                    // start new table
                    $currentTable = trim($m[1]);
                    $headers = [];
                    $rows    = [];
                }
                continue;
            }

            if ($headers === []) {
                $headers = str_getcsv($line);
                $headers = array_map(fn($h) => (string)trim($h), $headers);
                continue;
            }

            // data row
            $fields = str_getcsv($line);
            $row    = [];
            foreach ($headers as $i => $h) {
                $val = $fields[$i] ?? null;
                if (\is_string($val) && strtoupper(trim($val)) === 'NULL') $val = null;
                $row[$h] = $val;
            }
            $rows[] = $row;
        }

        if ($currentTable !== '') {
            self::finalizeTable($tables, $currentTable, array_map(
                fn($h) => ['name' => $h, 'def' => 'TEXT'], $headers
            ), $rows);
        }

        return [
            'name'      => $dbName,
            'charset'   => 'utf-8',
            'collation' => 'utf8_general_ci',
            'tables'    => $tables
        ];
    }

    /**
     * Import from a MySQL-style SQL dump produced by exportToSQL().
     */
    public static function importFromSQL(string $raw, string $fallbackName): array{
        $charset  = 'utf-8';
        $collate  = 'utf8_general_ci';
        $dbName   = $fallbackName;
        $tables   = [];

        
        if (preg_match('/DEFAULT\s+CHARSET=([a-z0-9_]+)/i', $raw, $m)) $charset = $m[1];
        if (preg_match('/COLLATE=([a-z0-9_]+)/i', $raw, $m))          $collate = $m[1];


        // CREATE TABLE `name` ( `col` DEF, ... ) ENGINE=...
        $reCreate = '/CREATE\s+TABLE\s+`([^`]+)`\s*\((.*?)\)\s*(?:ENGINE|;)/is';
        preg_match_all($reCreate, $raw, $matches, PREG_SET_ORDER);
        foreach ($matches as $mt) {
            $tableName = (string)$mt[1];
            $block     = (string)$mt[2];
            $columns   = [];

            $lines = preg_split("/,\s*\r?\n/", $block);
            foreach ($lines as $ln) {
                if (preg_match('/^\s*`([^`]+)`\s+(.+?)\s*$/m', $ln, $cm)) {
                    $colName = (string)$cm[1];
                    $def     = (string)trim($cm[2]);
                    // skip constraints
                    $upper = strtoupper($colName);
                    if (\in_array($upper, ['PRIMARY','UNIQUE','KEY','CONSTRAINT'], true)) continue;
                    $columns[$colName] = $def;
                }
            }
            self::finalizeTable($tables, $tableName, $columns, []);
        }

        // INSERT INTO `name` (`c1`,`c2`) VALUES ('v1','v2');
        $reInsert = '/INSERT\s+INTO\s+`([^`]+)`\s*\(`([^`]+(?:`\s*,\s*`[^`]+)*)`\)\s*VALUES\s*\((.*?)\)\s*;/is';
        preg_match_all($reInsert, $raw, $rowsM, PREG_SET_ORDER);
        foreach ($rowsM as $im) {
            $tname       = (string)$im[1];
            $colListRaw  = (string)$im[2];
            $valuesRaw   = (string)$im[3];

            $colNames = [];
            $parts = explode(',', $colListRaw);
            foreach ($parts as $p) $colNames[] = trim($p, " \t\n\r\0\x0B`");

            $vals = self::splitSqlValues($valuesRaw);

            $row = [];
            foreach ($colNames as $i => $col) {
                $v = $vals[$i] ?? null;
                if ($v === 'NULL') $v = null;
                $row[$col] = $v;
            }

            $key = strtolower($tname);
            if (!isset($tables[$key])) {
                $cols = [];
                foreach ($colNames as $c) $cols[$c] = 'TEXT';
                self::finalizeTable($tables, $tname, $cols, []);
            }
            $tables[$key]['rows'][] = $row;
        }

        return [
            'name'      => $dbName,
            'charset'   => $charset,
            'collation' => $collate,
            'tables'    => $tables
        ];
    }

    /**
     * Import from an SQLite-style SQL dump produced by exportToSQLite().
     */
    public static function importFromSQLite(string $raw, string $fallbackName): array
    {
        $dbName = $fallbackName;
        $tables = [];

        // CREATE TABLE "name" ( "col" DEF, ... );
        $reCreate = '/CREATE\s+TABLE\s+"([^"]+)"\s*\((.*?)\)\s*;/is';
        preg_match_all($reCreate, $raw, $matches, PREG_SET_ORDER);
        foreach ($matches as $mt) {
            $tableName = (string)$mt[1];
            $block     = (string)$mt[2];
            $columns   = [];

            $lines = preg_split("/,\s*\r?\n/", $block);
            foreach ($lines as $ln) {
                if (preg_match('/^\s*"([^"]+)"\s+(.+?)\s*$/m', $ln, $cm)) {
                    $colName = (string)$cm[1];
                    $def     = (string)trim($cm[2]);
                    $upper   = strtoupper($colName);
                    if (in_array($upper, ['PRIMARY','UNIQUE','KEY','CONSTRAINT'], true)) continue;
                    $columns[$colName] = $def;
                }
            }
            self::finalizeTable($tables, $tableName, $columns, []);
        }

        // INSERT INTO "name" ("c1","c2") VALUES ('v1','v2');
        $reInsert = '/INSERT\s+INTO\s+"([^"]+)"\s*\("([^"]+(?:"\s*,\s*"[^"]+)*)"\)\s*VALUES\s*\((.*?)\)\s*;/is';
        preg_match_all($reInsert, $raw, $rowsM, PREG_SET_ORDER);
        foreach ($rowsM as $im) {
            $tname       = (string)$im[1];
            $colListRaw  = (string)$im[2];
            $valuesRaw   = (string)$im[3];

            $trimmed = trim($colListRaw);
            $trimmed = preg_replace('/"\s*,\s*"/', '","', $trimmed);
            $colNames = array_map(fn($s) => (string)trim($s, '"'), explode('","', $trimmed));

            $vals = self::splitSqlValues($valuesRaw);

            $row = [];
            foreach ($colNames as $i => $col) {
                $v = $vals[$i] ?? null;
                if ($v === 'NULL') $v = null;
                $row[$col] = $v;
            }

            $key = strtolower($tname);
            if (!isset($tables[$key])) {
                $cols = [];
                foreach ($colNames as $c) $cols[$c] = 'TEXT';
                self::finalizeTable($tables, $tname, $cols, []);
            }
            $tables[$key]['rows'][] = $row;
        }

        // SQLite dumps don't carry charset/collation; use sensible defaults
        return [
            'name'      => $dbName,
            'charset'   => 'utf-8',
            'collation' => 'utf8_general_ci',
            'tables'    => $tables
        ];
    }

    // ------------------ IMPORT HELPERS ------------------

    /**
     * Robust splitter for SQL VALUES lists:
     * e.g., 'a','b',NULL,'c''d',123  => ["a","b","NULL","c'd","123"]
     */
    private static function splitSqlValues(string $values) : array
    {
        $out = [];
        $buf = '';
        $inQuote = false;
        $quoteChar = '';
        $len = \strlen($values);
        for ($i = 0; $i < $len; $i++) {
            $ch = $values[$i];
            if ($inQuote) {
                if ($ch === $quoteChar) {
                    // doubled quotes inside SQL string: '' -> '
                    $next = ($i + 1 < $len) ? $values[$i + 1] : null;
                    if ($next === $quoteChar) { $buf .= $quoteChar; $i++; continue; }
                    $inQuote = false;
                    continue;
                }
                $buf .= $ch;
            } else {
                if ($ch === "'" || $ch === '"') {
                    $inQuote = true;
                    $quoteChar = $ch;
                } elseif ($ch === ',') {
                    $out[] = trim($buf);
                    $buf = '';
                } else {
                    $buf .= $ch;
                }
            }
        }
        if ($buf !== '') $out[] = trim($buf);
        // unwrap quotes; keep NULL literal
        return array_map(function ($t) {
            $t = trim($t);
            if ($t === '') return '';
            if (strtoupper($t) === 'NULL') return 'NULL';
            if ((strlen($t) >= 2) && ($t[0] === "'" && substr($t, -1) === "'" || $t[0] === '"' && substr($t, -1) === '"')) {
                $inner = substr($t, 1, -1);
                $inner = str_replace("''", "'", $inner);
                return $inner;
            }
            return $t;
        }, $out);
    }

    /**
     * Normalize and attach a table to the $tables accumulator.
     * $columns may be an assoc [name => def] or a list of ['name'=>..,'def'=>..].
     */
    private static function finalizeTable(array &$tables, string $tblName, array $columns, array $rows): void
    {
        if ($tblName === '') return;

        // Normalize columns into assoc [name => def]
        $colsAssoc = [];
        foreach ($columns as $k => $def) {
            if (\is_int($k) && \is_array($def) && isset($def['name'])) {
                $colsAssoc[(string)$def['name']] = (string)($def['def'] ?? 'TEXT');
            } elseif (\is_int($k)) {
                $colName = (string)$def;
                $colsAssoc[$colName] = 'TEXT';
            } else {
                $colsAssoc[(string)$k] = (string)$def;
            }
        }

        $tables[strtolower($tblName)] = [
            'name'    => $tblName,
            'columns' => $colsAssoc,
            'rows'    => \is_array($rows) ? $rows : []
        ];
    }
    
    /**
     * Map database charset names (e.g., MySQL) to mbstring encoding names.
     */
    public static function mbTargetEncoding(string $charset): string{
        switch (strtolower(trim($charset))) {
            case 'utf8mb4':
            case 'utf8':
            case 'utf-8':
                return 'UTF-8';

            case 'latin1':
            case 'iso-8859-1':
            case 'iso_8859-1':
                return 'ISO-8859-1';

            case 'windows-1252':
            case 'cp1252':
                return 'Windows-1252';

            default:
                return 'UTF-8'; // safe fallback
        }
    }




    /**
     * Perform a SQL-like JOIN between two tables in the currently opened database.
     *
     * Supported join types (case-insensitive; synonyms accepted):
     *  - 'inner'  / 'INNER JOIN'
     *  - 'left'   / 'LEFT JOIN'
     *  - 'right'  / 'RIGHT JOIN'
     *  - 'cross'  / 'CROSS JOIN' (Cartesian product; ignores $on)
     *
     * ON clause can be provided as:
     *  - array mapping: [ 'table1.col' => 'table2.col', ... ]
     *  - string:       "table1.col = table2.col AND table1.other = table2.other"
     *  - null:         only valid for CROSS JOIN; for other joins you must specify ON.
     *
     * Result rows use namespaced keys to avoid collisions: 'table1.column' and 'table2.column'.
     * Optionally you can provide $order like 'table1.column ASC' or 'table2.column DESC'.
     */
    public static function join(PHPDB $db, string $table1, string $table2, string $joinType = 'inner', array|string|null $on = null, ?string $order = null): array
    {
        // Fetch rows (fetchAll ensures can_view and requires the DB to be open)
        $rows1 = $db->fetchAll($table1);
        $rows2 = $db->fetchAll($table2);

        // Normalize join type (accepts 'INNER JOIN', etc.)
        $t = strtolower(trim($joinType));
        $t = str_replace(' join', '', $t);
        if (!\in_array($t, ['inner','left','right','cross'], true)) {
            throw new PHPDBException("Unsupported join type: {$joinType}");
        }

        // Parse ON pairs for non-cross joins
        $pairs = [];
        if ($t !== 'cross') {
            if ($on === null) {
                throw new PHPDBException('ON clause is required for INNER/LEFT/RIGHT joins.');
            }
            if (\is_array($on)) {
                foreach ($on as $l => $r) { $pairs[] = [ (string)$l, (string)$r ]; }
            } else {
                $s = (string)$on;
                $chunks = preg_split('/\s+AND\s+/i', $s);
                foreach ($chunks as $chunk) {
                    if (preg_match('/^\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*$/', $chunk, $m) === 1) {
                        $pairs[] = [ $m[1], $m[2] ];
                    } else {
                        throw new PHPDBException('Unsupported ON clause fragment: ' . $chunk);
                    }
                }
            }
            if ($pairs === []) throw new PHPDBException('ON clause produced no column pairs.');
        }

        // Helper: get value either by 'col' or 'table.col'
        $getVal = function(array $row, string $ident, string $tblName) {
            $ident = trim($ident);
            $parts = explode('.', $ident, 2);
            if (\count($parts) === 2) {
                [$pTable, $pCol] = $parts;
                if (strtolower($pTable) !== strtolower($tblName)) return null;
                return $row[$pCol] ?? null;
            }
            return $row[$ident] ?? null;
        };

        $out = [];

        if ($t === 'cross') {
            foreach ($rows1 as $r1) {
                foreach ($rows2 as $r2) {
                    $out[] = self::combineRows($table1, $r1, $table2, $r2);
                }
            }
        } else {
            $doMatch = function(array $r1, array $r2) use ($pairs, $getVal, $table1, $table2) {
                foreach ($pairs as [$l, $r]) {
                    $lv = $getVal($r1, $l, $table1);
                    $rv = $getVal($r2, $r, $table2);
                    if ($lv !== $rv) return false;
                }
                return true;
            };

            if ($t === 'inner' || $t === 'left') {
                foreach ($rows1 as $r1) {
                    $matched = false;
                    foreach ($rows2 as $r2) {
                        if ($doMatch($r1, $r2)) { $out[] = self::combineRows($table1, $r1, $table2, $r2); $matched = true; }
                    }
                    if (!$matched && $t === 'left') { $out[] = self::combineRows($table1, $r1, $table2, []); }
                }
            } else { // right
                foreach ($rows2 as $r2) {
                    $matched = false;
                    foreach ($rows1 as $r1) {
                        if ($doMatch($r1, $r2)) { $out[] = self::combineRows($table1, $r1, $table2, $r2); $matched = true; }
                    }
                    if (!$matched) { $out[] = self::combineRows($table1, [], $table2, $r2); }
                }
            }
        }

        // Optional order
        if ($order !== null && trim($order) !== '') {
            if (preg_match('/^\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*(ASC|DESC)?\s*$/i', $order, $m)) {
                $orderCol = $m[1];
                $orderDir = (isset($m[2]) && strtoupper($m[2]) === 'DESC') ? 'DESC' : 'ASC';
                usort($out, function($a, $b) use ($orderCol, $orderDir) {
                    $va = $a[$orderCol] ?? null;
                    $vb = $b[$orderCol] ?? null;
                    if ($va === $vb) return 0;
                    if ($va === null) return ($orderDir === 'ASC') ? -1 : 1;
                    if ($vb === null) return ($orderDir === 'ASC') ? 1 : -1;
                    $cmp = is_numeric($va) && is_numeric($vb) ? $cmp = ($va + 0) <=> ($vb + 0) : strcmp((string)$va, (string)$vb) ;
                    return ($orderDir === 'ASC') ? $cmp : -$cmp;
                });
            }
        }

        return $out;
    }

    /**
     * Combine two rows with namespaced keys: 'table1.column' and 'table2.column'.
     */
    private static function combineRows(string $t1, array $r1, string $t2, array $r2): array{
        $out = [];
        foreach ($r1 as $k => $v) { $out["{$t1}.{$k}"] = $v; }
        foreach ($r2 as $k => $v) { $out["{$t2}.{$k}"] = $v; }
        return $out;
    }
}
/**
 * PHPDB Exception
 */
class PHPDBException extends \Exception {
    // Custom exception for PHPDB
    public function __construct(string $message, int $code = 0, ?\Throwable $previous = null){
        parent::__construct($message, $code, $previous);
    }
}
/**
 * PHPDB Security measures
 */
class PHPDBSecurity {
    public const EX_LOCK = 'lock';
    public const EX_UNLOCK = 'unlock';
    /**
     * Prevent direct instantiation
     */
    public function __construct(){
        // Prevent direct instantiation
    }
    /**
     * Prevent direct access to this file
     * @return void
     */
    public static function preventDirectAccess(): void{
        // Prevent direct web access to this library file
        if (PHP_SAPI === 'cli') return;
        $script = basename((string)($_SERVER['SCRIPT_FILENAME'] ?? $_SERVER['PHP_SELF'] ?? ''));
        if ($script === basename(__FILE__)) {
            header('HTTP/1.1 403 Forbidden');
            exit('Direct access to this file is forbidden.');
        }
    }
    
    
    /**
     * Blocks ONLY .phpdb file extensions via .htaccess in a given folder.
     * Apache 2.4+: "Require all denied"
     * Apache 2.2 (legacy): "Order allow,deny / Deny from all"
     *
     * @param string $dbPath Path to the database folder
     * @param string $mode   Mode (lock|unlock)
     * @return void
     */
    public static function secureDatabase(string $dbPath, string $mode = self::EX_LOCK): void{
        // Restrict to a canonical directory path
        $canon = self::canonicalPath($dbPath);
        if ($canon === null) return;
        $dbPath = rtrim($canon, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;


        $htaccessPath = rtrim($dbPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.htaccess';

        // Build content that works on both Apache 2.4+ and 2.2
        // NOTE: Do not HTML-escape; Apache expects raw directives.
        $htaccessContent = <<<'HTA'
    <IfModule mod_authz_core.c>
    <FilesMatch "(\.phpdb$|^phpdb\.json$|^phpdb_auth_state\.json$|^phpdb_audit\.log$|^phpdb_pepper\.secret$)">
        Require all denied
    </FilesMatch>
    </IfModule>
    <IfModule !mod_authz_core.c>
    <FilesMatch "(\.phpdb$|^phpdb\.json$|^phpdb_auth_state\.json$|^phpdb_audit\.log$|^phpdb_pepper\.secret$)">
        Order allow,deny
        Deny from all
    </FilesMatch>
    </IfModule>
    HTA;

        // Also build the NGINX snippet we'll manage alongside .htaccess
        $nginxPath = rtrim($dbPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'nginx.conf';
        $nginxConf = <<<'NGX'
    # PHPDB NGINX snippet - include this in your server {} or include the file.
    # Deny access to .phpdb files and sensitive PHPDB files
    location ~* \.phpdb$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    location = /phpdb.json { deny all; access_log off; log_not_found off; }
    location = /phpdb_auth_state.json { deny all; access_log off; log_not_found off; }
    location = /phpdb_audit.log { deny all; access_log off; log_not_found off; }
    location = /phpdb_pepper.secret { deny all; access_log off; log_not_found off; }
    NGX;
       
        if ($mode === self::EX_UNLOCK) {
            // For unlocking, remove only the managed snippets from existing files (do NOT delete the files)
            if (is_file($htaccessPath)) {
                $existing = @file_get_contents($htaccessPath);
                if ($existing === false) $existing = '';

                // Normalize line endings for robust matching and removal
                $normExisting = preg_replace('/\r\n|\r|\n/', "\n", $existing);
                $normSnippet  = preg_replace('/\r\n|\r|\n/', "\n", $htaccessContent);

                // Remove the snippet (if present) in a newline-agnostic way
                if (strpos($normExisting, $normSnippet) !== false) {
                    // Use preg_replace on original content with a tolerant pattern to preserve surrounding content
                    $pattern = '/(?:\r\n|\n|\r)?' . preg_quote($htaccessContent, '/') . '/s';
                    $new = @preg_replace($pattern, '', $existing);
                    if ($new === null) {
                        // fallback: remove normalized snippet from normalized content and convert back to original line endings
                        $newNorm = str_replace($normSnippet, '', $normExisting);
                        $new = preg_replace('/\n/', PHP_EOL, $newNorm);
                    }
                    // Trim extraneous whitespace/newlines
                    $new = preg_replace('/^\s+|\s+$/u', '', $new);
                    if ($new !== $existing) {
                        @file_put_contents($htaccessPath, $new, LOCK_EX);
                    }
                }
            }

            if (is_file($nginxPath)) {
                $existingN = @file_get_contents($nginxPath);
                if ($existingN === false) $existingN = '';

                $normExistingN = preg_replace('/\r\n|\r|\n/', "\n", $existingN);
                $normSnippetN  = preg_replace('/\r\n|\r|\n/', "\n", $nginxConf);

                if (strpos($normExistingN, $normSnippetN) !== false) {
                    $patternN = '/(?:\r\n|\n|\r)?' . preg_quote($nginxConf, '/') . '/s';
                    $newN = @preg_replace($patternN, '', $existingN);
                    if ($newN === null) {
                        $newNormN = str_replace($normSnippetN, '', $normExistingN);
                        $newN = preg_replace('/\n/', PHP_EOL, $newNormN);
                    }
                    $newN = preg_replace('/^\s+|\s+$/u', '', $newN);
                    if ($newN !== $existingN) {
                        @file_put_contents($nginxPath, $newN, LOCK_EX);
                    }
                }
            }
            return;
        }
            // If the file does not exist, create it; if it exists and doesn't already contain
            // the snippet, append the snippet; if the snippet is already present, do nothing.
            $existing = is_file($htaccessPath) ? @file_get_contents($htaccessPath) : '';
            if ($existing === false) $existing = '';

            $normExisting = preg_replace('/\r\n|\r|\n/', "\n", $existing);
            $normSnippet  = preg_replace('/\r\n|\r|\n/', "\n", $htaccessContent);

            if (trim($normExisting) === '') {
                // create new file with content
                @file_put_contents($htaccessPath, $htaccessContent, LOCK_EX);
            } else {
                // append only if the snippet is not already present (compare normalized strings)
                if (strpos($normExisting, $normSnippet) === false) {
                    // ensure we append on a new line
                    $append = PHP_EOL . $htaccessContent;
                    @file_put_contents($htaccessPath, $append, FILE_APPEND | LOCK_EX);
                }
            }

            $existingN = is_file($nginxPath) ? @file_get_contents($nginxPath) : '';
            if ($existingN === false) $existingN = '';

            $normExistingN = preg_replace('/\r\n|\r|\n/', "\n", $existingN);
            $normSnippetN  = preg_replace('/\r\n|\r|\n/', "\n", $nginxConf);

            if (trim($normExistingN) === '') {
                @file_put_contents($nginxPath, $nginxConf, LOCK_EX);
            } else {
                if (strpos($normExistingN, $normSnippetN) === false) {
                    @file_put_contents($nginxPath, PHP_EOL . $nginxConf, FILE_APPEND | LOCK_EX);
                }
            }
    }



    /**
     * Escape the string
     * @param string $str Input string
     * @return string Escaped string
     */
    public static function escape(string $str): string{
        return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
    
    /**
     * Set the security headers
     * @return void
     */
    public static function sendSecureHeaders(): void{
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header('Permissions-Policy: interest-cohort=()'); // disable FLoC-like features
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }

    
    /**
     * Get the canonical path
     * @param string $path Input path
     * @param ?string $baseDir Optional base directory to restrict the path
     * @return ?string Canonical path or null if invalid
     */
    public static function canonicalPath(string $path, ?string $baseDir = null): ?string{
        // Normalize slashes and resolve symlinks/.. elements
        $real = realpath($path);
        if ($real === false) return null;

        if ($baseDir !== null) {
            $base = realpath($baseDir);
            if ($base === false) return null;
            // Ensure $real is inside $base
            if (strpos($real, $base) !== 0) return null;
        }
        return $real;
    }
    
    /**
     * Timing-safe string comparison
     * @param string $known Known string
     * @param string $user User string
     * @return bool True if equal, false otherwise
     */
    public static function timingSafeEquals(string $known, string $user): bool{
        if (function_exists('hash_equals')) 
            return hash_equals($known, $user);
        // Fallback if hash_equals is unavailable
        $lenKnown = \strlen($known);
        $lenUser  = \strlen($user);
        $status   = $lenKnown ^ $lenUser;
        $len      = min($lenKnown, $lenUser);
        for ($i = 0; $i < $len; $i++) 
            $status |= \ord($known[$i]) ^ \ord($user[$i]);
        return $status === 0;
    }
    /**
     * Write an audit log entry
     * @param string $message Log message
     * @param ?string $logFile Optional log file path (default: phpdb_audit.log in current directory)
     * @return void
     */
    

// ---- Authentication throttling (best-effort file-based) -----------------------------
private static function authStateFile(): string {
    return __DIR__ . DIRECTORY_SEPARATOR . 'phpdb_auth_state.json';
}

/**
 * Build a client identifier for throttling.
 * Uses username + IP when available; falls back to 'cli'.
 */
private static function authClientId(string $username): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    return hash('sha256', "$username|$ip");
}


    /**
     * Checks if the user attempted to login 
     * @param string $username Username
     * @param int $maxAttempts Max attempts
     * @param int $windowSeconds Window time
     * @param int $lockSeconds Lockout time
     * @return bool TRUE if the user is locked out, else FALSE
     */
    public static function isLockedOut(string $username,int $maxAttempts = 5,int $windowSeconds = 300,int $lockSeconds = 900): bool {
        $id   = self::authClientId($username);
        $now  = time();
        $file = self::authStateFile();
        $state = [];

        if (is_file($file)) {
            $json = file_get_contents($file);
            $state = \is_string($json) ? json_decode($json, true) : [];
            if (!\is_array($state)) $state = [];
        }

        $entry = $state[$id] ?? ['fails' => [], 'locked_until' => 0];

        // If already locked, honor it
        $lockedUntil = (int)($entry['locked_until'] ?? 0);
        if ($lockedUntil > $now) {
            return true;
        }

        // Purge failures outside the sliding window
        $fails = array_filter(
            (array)($entry['fails'] ?? []),
            fn($t): bool => is_numeric($t) && ((int)$t) >= $now - $windowSeconds
        );
        $fails = array_values($fails);
        $entry['fails'] = $fails;

        // ✅ Enforce lockout here using maxAttempts + lockSeconds
        if (\count($fails) >= $maxAttempts) {
            $entry['locked_until'] = $now + $lockSeconds;
            $state[$id] = $entry;

            // Best-effort write-back
            @file_put_contents($file, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);
            return true;
        }

        // Not locked: keep state updated (purged fails + lock cleared)
        $entry['locked_until'] = 0;
        $state[$id] = $entry;

        // Best-effort write-back (non-fatal)
        @file_put_contents($file, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);

        return false;
    }


    /**
     * Record a failed login attempt and lock out if threshold exceeded.
     */
    public static function recordFailedLogin(string $username, int $maxAttempts = 5, int $windowSeconds = 300, int $lockSeconds = 900): void {
        $id = self::authClientId($username);
        $now = time();
        $file = self::authStateFile();
        $state = [];

        if (is_file($file)) {
            $json = file_get_contents($file);
            $state = \is_string($json) ? json_decode($json, true) : [];
            if (!\is_array($state)) $state = [];
        }

        $entry = $state[$id] ?? ['fails' => [], 'locked_until' => 0];
        $fails = array_filter((array)($entry['fails'] ?? []), fn($t) => is_numeric($t) && ((int)$t) >= ($now - $windowSeconds));
        $fails[] = $now;
        $entry['fails'] = array_values($fails);

        if (\count($entry['fails']) >= $maxAttempts) {
            $entry['locked_until'] = $now + $lockSeconds;
            self::auditLog("Auth lockout: user=" . ($username !== '' ? $username : "unknown") . " until=" . date('c', $entry['locked_until']));
        }

        $state[$id] = $entry;
        @file_put_contents($file, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);
    }

    /**
     * Clear failed login attempts for this user.
     */
    public static function clearFailedLogins(string $username): void {
        $id = self::authClientId($username);
        $file = self::authStateFile();
        if (!is_file($file)) return;
        $json = file_get_contents($file);
        $state = \is_string($json) ? json_decode($json, true) : [];
        if (!\is_array($state)) return;
        if (isset($state[$id])) {
            unset($state[$id]);
            @file_put_contents($file, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);
        }
    }
    public static function auditLog(string $message, ?string $logFile = null): void {
            if ($logFile === null) {
                $logFile = __DIR__ . DIRECTORY_SEPARATOR . 'phpdb_audit.log';
            }
            $timestamp = date('Y-m-d H:i:s');
            $entry = "[$timestamp] $message\n";
            file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
    }
    /**
     * Creates an account to the credentials file
     * @param string $key Account key
     * @param string $username Username
     * @param string $password Password
     * @param ?string $role User Role
     * @param array $databases List of database that can only be accesses; ['*'] = 'all database'
     * @param bool $can_write Can write into database
     * @param bool $can_create Can create the database
     * @param bool $can_view Can view the database
     * @param string $credPath Credentials path
     * @return bool TRUE if the account has been created, else false
     */
    public static function createAccount(string $key, string $username, string $password, ?string $role = 'user', array $databases = ['*'], bool $can_view=true, bool $can_write = false, bool $can_create = false, bool $can_delete=true, ?string $credPath = null): bool {
        $path = $credPath ?? (__DIR__ . DIRECTORY_SEPARATOR . 'phpdb.json');
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        // Load existing config or initialize a minimal one
        $cfg = [];
        if (is_file($path)) {
            $raw = @file_get_contents($path);
            $cfg = \is_string($raw) && trim($raw) !== '' ? json_decode($raw, true) : [];
            if (!\is_array($cfg)) $cfg = [];
        }

        if (!isset($cfg['accounts']) || !\is_array($cfg['accounts'])) {
            $cfg['accounts'] = [];
        }

        // Prevent overwriting existing account key
        if (isset($cfg['accounts'][$key])) {
            return false;
        }

        // Hash password (include server-side pepper if configured)
        $pepper = getenv('PHPDB_PEPPER');
        $toHash = $password;
        if ($pepper !== false && $pepper !== '') {
            $toHash = "$password$pepper";
        }
        $hash = password_hash($toHash, PASSWORD_DEFAULT, ['cost' => 12]);
        if ($hash === false) return false;

        // Insert new account
        $cfg['accounts'][$key] = [
            'username'      => $username,
            'password' => $hash,
            'role'          => $role,
            'databases'     => $databases,
            'can_write'     => (bool)$can_write,
            'can_create'    => (bool)$can_create,
            'can_view'      => (bool)$can_view,
            'can_delete'      => (bool)$can_delete,
        ];

        $json = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) return false;

        $written = @file_put_contents($path, $json, LOCK_EX);
        return $written !== false;
    }

}
