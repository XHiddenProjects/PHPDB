# PHPDB
PHPDB is a lightweight, encrypted, file‑based database for PHP offering tables, type validation, foreign‑key enforcement, config‑driven roles, atomic writes with crash recovery, backups, and import/export (JSON/CSV/SQL/SQLite). Ideal for secure, portable data in embedded apps and CLI tools.

## Introduction
PHPDB is a flat-file database that involves encryption to store databases and multiple tables all in small amount to terms. It's the middle ground between **MySQL** and **SQLite**. This software does use SQL syntax when it comes to **conditions**: Refer to [SQL Syntax](https://www.tutorialspoint.com/sql/sql-syntax.htm) for better understanding. 

There are 4 avaliable class that you can use `PHPDB`, `PHPDBUtils`, `PHPDBException`, and `PHPDBSecurity`. 

- `PHPDB` is the main class that you will call in order to create things.
- `PHPDBUtils` is utilities method for easier use of the database.
- `PHPDBSecurity` is extra security measures to the database.
- `PHPDBException` is extra security measures to the database.

## Getting started
To get started, lets starting with basic requirements and security procedures.
```php
<?php
# Load in necessary classes
require_once __DIR__ . '/phpdb.php';
use XHiddenProjects\PHPDB\PHPDB;
use XHiddenProjects\PHPDB\PHPDBSecurity;
use XHiddenProjects\PHPDB\PHPDBUtils;
use XHiddenProjects\PHPDB\PHPDBException;
# Define paths
!defined('DIR') ? define('DIR',__DIR__);
!defined('DATABASES') ? define('DATABASES',__DIR__.DIRECTORY_SEPARATOR.'databases');
!defined('CREDENTIALS') ? define('CREDENTIALS',__DIR__.DIRECTORY_SEPARATOR.'phpdb.json');
# Lock any access to any files
PHPDBSecurity::secureDatabase(DIR, PHPDBSecurity::EX_LOCK);
# Create an account if the phpdb.json doesn't exist. These will be saved as a JSON object inside of **phpdb.json** and password WILL be hashed
if(!file_exists(CREDENTIALS)){
  PHPDBSecurity::createAccount(
        key: 'admin', # Account key
        username: 'admin', # Username
        password: '', # Password
        role: 'admin', # Rold
        databases: ['*'], # Databases the user can access, ['*'] = all databases
        can_view: true, # Can view the database
        can_write: true, # Can write the database
        can_create: true, # Can create the database
        can_delete: true, # Can delete the database
        credPath: CREDENTIALS # Credentials path (optional)
    );
}
# Create the object
$db = new PHPDB(CREDENTIALS);
try{
# Insert code here
}catch (PHPDBException $e) {
    echo "❌ PHPDBException: " . $e->getMessage() . PHP_EOL;
} catch (Throwable $e) {
    echo "❌ Unexpected error: " . $e->getMessage() . PHP_EOL;
}
```

## Authorizing
This is a requirement before loading in a script

```php
# Authorize your account.
$db->authorize($usernameOrAccountKey, $password);
```
> **Warning:** You may have to reauthorize evertime you close, and reopen the database
***
## Databases
This section is about databases

## Creating a database
To create a database use the `createDatabase()`
```php
$dbName = 'myapp';
/**
  * Creates a database
  * @param string $name Database name
  * @param string $path Database location path
  * @param string $charset Character set
  * @param string $collation Collation
  * @throws PHPDBException
  * @return void
  */
$db->createDatabase($dbName,DATABASES,'utf-8','utf8_general_ci');
```
### Backing up databases
To back up the database use the `backUpDatabase()` method
```php
# Backup your database
$db->backUpDatabase($dbName, __DIR__.DIRECTORY_SEPARATOR.'backups');
```

### Importing/Exporting databases
You can _export_ and _import_ databases from `JSON`, `MySQL`, `SQLite`, and `CSV` files.
```php
# Export: replace "json" with any other format
$db->export($dbName, 'json');
# Import:  replace "json" with any other format
$db->import($path_to_exported_file, 'json');
```

### Restoring database
To restore the database use the `restoreDatabase()`
```php
# Restore the database
$db->restoreDatabase($dbName,  __DIR__.DIRECTORY_SEPARATOR.'backups');
```

## Opening/Closing databases
To open the database use the `open()` and to close use the `close()`
```php
# Open
$db->open($dbName);
# close
$db->close($dbName);
```

## Deleting a database
To delete the database use `dropDatabase()` method
```php
# Deleting a database
$db->dropDatabase($dbName);
```
***
## Tables
This section is about tables and data inside of tables

### Creating tables
To create a table in the database use the `createTable()` and to check if the table exists use `tableExists()`. This is where **SQL syntax** comes in.
```php
$tbl = 'users';
# Check if the table exists
if(!$db->tableExists($tbl)){
  # Create a table
  $db->createTable($tbl,[
    'id' => 'INT AUTO_INCREMENT UNIQUE',
    'username' => 'VARCHAR(50) UNIQUE NOT NULL',
    'age' => 'INT NOT NULL',
    'score' => 'FLOAT NOT NULL',
    'created' => 'DATETIME NOT NULL'
  ]);
}
```

### Deleteing tables
To delete tables use the `dropTable()` method
```php
# Delete the table
$db->dropTable($tbl);
```

### renameTable
To rename tables use the `renameTable()` method
```php
# Rename the table
$db->renameTable($tbl,'user');
```

### Listing tables
To list all the created tables use the `listTables()` method
```php
# List all the tables
foreach($db->listTables as $tables){
...
}
```
***
## Data
The section is about how to modify data inside of [tables](#tables)

### Inserting data
To insert data, use the `insert()` method
```php
# Insert data inside the able
# Example of the SQL syntax
# ['id'=>'INT AUTO_INCREMENT UNIQUE','item'=>'VARCHAR(100) NOT NULL'];
$db->insert($tbl, [
'column_name'=>'SQL syntax here'
]);
```

### Updating data
To update the data, use the `update()` method.
```php
$db->update($tbl,[
  'column_name'=>'colume_value'
], 'SQL_WHERE_syntax');
```
> **Note:** IF the condition is a `string` then it must have the  _"WHERE"_ keyword

### Deleteing data
To delete a data from the table, use the `delete()` method
```php
$db->delete($tbl,'SQL_WHERE_SYNTAX');
```
> **Note:** IF the condition is a `string` then it must have the _"WHERE"_ keyword

### Fetching data
To fetch a singular data, use the `fetch()` and if you multiple, use `fetchAll()`
**Note:** you can also use the `ORDER BY` to sort your dataset

```php
# Fetch only a singular result
$db->fetch($tbl, 'SQL_WHERE_SYNTAX_AND_ORDER_BY_SYNTAX');

# Fetch All the results
$db->fetchAll($tbl, 'SQL_WHERE_SYNTAX_AND_ORDER_BY_SYNTAX');
```
> **Note:** IF the condition is a `string` then it must have the  _"WHERE"_ keyword

## Security
This section is about how to use the best security practices of _PHPDB_

### Crash Recovery
To recover any crashes use the `crashRecovery()` method
```php
# Recover any crashes
$db->crashRecovery($dbName);
```

### Prevent direct access
To prevent direct access to the phpdb.php file, use `preventDirectAccess()`
```php
# Blocks the phpdb.php file access
PHPDBSecurity::preventDirectAccess();
```

### Securing the database
To secure the database, use the `secureDatabase()` method
```php
# Use `EX_UNLOCK` to remove the security
PHPDBSecurity::secureDatabase(__DIR__,PHPDBSecurity::EX_LOCK);
```

### Escaping text
To escape the text before inserting, use the `escape()` method
```php
# Escape the string
PHPDBSecurity::escape('string');
```

### Sending a secure header
To secure the header, use the `sendSecureHeaders()` method
```php
# Secure the headers
PHPDBSecurity::sendSecureHeaders();
```

### canonicalPath
To get the canonical path, use the `canonicalPath()` method
```php
# Get the canoical path
PHPDBSecurity::canonicalPath(string $path, ?string $baseDir = null);
```

### Lockouts
To prevent lockouts, use the `isLockedOut()`
> The class already includes a safeguard for this. To change the lockout settings, go to the `Authorize()` and at the end of the parameter with the lockout settings
> ```php
>$db->Authorize($username,$password,['max_attempts'=>5, 'windows_seconds'=>300, 'lock_seconds'=>900]);
> ``` 

### Creating an account
To create an account, use the `createAccount()` method
```php
PHPDBSecurity::createAccount(
key,
username,
password,
?role,
?databases,
?can_view,
?can_write,
?can_create,
?can_delete,
?credPath 
);
```

### Audits
To audit any issues, use the `auditLog()` method
> **Audits** are always active through the class, so if any issues occur it will log it into the file, so you can see where it's located; File: `__DIR__.DIRECTORY_SEPARATOR.'phpdb_audit.log'`;

## Utilities
This section is using using the utilites, usage

### Find
Find any results through the dataset, use the `find()` method

```php
# Find the results base on keysearch. Returns as an array or null if empty
PHPDBUtils::find(PHPDB $PHPDB, string $tableName, string $columnName, string $searchTerm, ?callable $output=null);
```

### search
Searchs if the context exists
```php
# Search for a certin context in the table. Returns boolean
PHPDBUtils::search(PHPDB $PHPDB, string $tableName, string $searchTerm);
```

### Counting rows
To return the number of rows that are in the table, use the `countRows()` method
```php
# Count the number of rows
PHPDBUtils::countRows(PHPDB $PHPDB, string $tableName)
```

### Filter
Filters the `fetchAll()` results, use the `filter()` method
```php
# Filter the results
PHPDBUtils::filter(PHPDB $PHPDB, string $tableName, callable $callback);
```

### Indexs
Create an index using the `createIndex()`, update index using the `updateIndex()`, delete indexes using `dropIndex()`, and list the indexes using `listIndexes()`
```php
# Create index
PHPDBUtils::createIndex(PHPDB $PHPDB, string $tableName, string $columnName);
# Update
PHPDBUtils::updateIndex(PHPDB $PHPDB, string $tableName, string $columnName);
# Delete
PHPDBUtils::dropIndex(PHPDB $PHPDB, string $tableName, string $columnName)
# List
PHPDBUtils::listIndexes(PHPDB $PHPDB, string $tableName)
```

### Condition builder
Use this to easily build a SQL WHERE condition string, use the `conditionBuilder()` method
```php
# Build a condition
PHPDBUtils::conditionBuilder(array $conditions);
```
