<?php

declare(strict_types=1);

/**
 * 普通查询示例：验证 amphp/mysql 连接池可用（订阅示例的辅助查询也走它）。
 *
 * 运行：
 *   MYSQL_DSN='host=127.0.0.1 user=root password=... db=test' php examples/query.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Amp\Mysql\MysqlConfig;
use Amp\Mysql\MysqlConnectionPool;

$dsn = \getenv('MYSQL_DSN') ?: 'host=127.0.0.1 user=root password= db=test';

Amp\async(function () use ($dsn) {
    $pool = new MysqlConnectionPool(MysqlConfig::fromString($dsn));

    foreach ($pool->execute('SELECT NOW() AS now, @@version AS version') as $row) {
        \printf("connected: MySQL %s @ %s\n", $row['version'], $row['now']);
    }
})->await();
