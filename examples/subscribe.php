<?php

declare(strict_types=1);

/**
 * 订阅示例：把当前进程注册为 MySQL 从库，实时拉取并解析 binlog 事件。
 *
 * 运行：
 *   MYSQL_DSN='host=127.0.0.1 user=root password=... db=test' php examples/subscribe.php
 *
 * 账号需要 REPLICATION SLAVE 权限。
 */

require __DIR__ . '/../vendor/autoload.php';

use Amp\Mysql\MysqlConfig;
use Amp\Mysql\MysqlConnectionPool;
use Tikobus\PhpBinlogAsync\BinlogConnection;
use Tikobus\PhpBinlogAsync\BinlogParser;
use Tikobus\PhpBinlogAsync\EventType;

$dsn = \getenv('MYSQL_DSN') ?: 'host=127.0.0.1 user=root password= db=test';
const REPLICA_SERVER_ID = 8101; // 伪装从库的唯一 server-id，不能与主库相同

// TIMESTAMP 列在 binlog 里按 UTC epoch 存储，这里按主库时区显示（按需调整）
\date_default_timezone_set('Asia/Shanghai');

Amp\async(function () use ($dsn) {
    // ── 1. 用普通的 amphp/mysql 连接池做辅助查询：订阅起点 + 列名 ──────────────
    $pool = new MysqlConnectionPool(MysqlConfig::fromString($dsn));
    $config = MysqlConfig::fromString($dsn);

    // 订阅起点：默认从主库当前位点开始（8.4+ 用 SHOW BINARY LOG STATUS，旧版用 SHOW MASTER STATUS）
    try {
        $rows = \iterator_to_array($pool->execute('SHOW BINARY LOG STATUS'), false);
    } catch (Throwable) {
        $rows = \iterator_to_array($pool->execute('SHOW MASTER STATUS'), false);
    }
    [$file, $pos] = [$rows[0]['File'], (int) $rows[0]['Position']];

    // 边界处理：若位点正好在文件末尾（等于当前写头），从文件头 4 开始订阅。
    // 否则 MySQL 8.4 的 dump 线程会回退去读最老的 binlog 文件并报 "binlog truncated"。
    foreach ($pool->execute('SHOW BINARY LOGS') as $log) {
        if ($log['Log_name'] === $file && $pos >= (int) $log['File_size']) {
            $pos = 4; // 服务器会先重发 FDE / PREVIOUS_GTIDS 等基础事件，然后等待新事件
        }
    }

    // 列名：binlog_row_metadata=MINIMAL 时 TABLE_MAP 事件不带列名，从 information_schema 补齐
    $columnNames = [];
    foreach ($pool->execute(
        "SELECT table_schema, table_name, column_name FROM information_schema.columns
         WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema')
         ORDER BY table_schema, table_name, ordinal_position",
    ) as $column) {
        $columnNames[\strtolower($column['TABLE_SCHEMA'] . '.' . $column['TABLE_NAME'])][] = $column['COLUMN_NAME'];
    }

    echo "以 server-id=", REPLICA_SERVER_ID, " 注册为从库，从 {$file}:{$pos} 开始订阅 binlog…\n",
        "（提示：在 MySQL 里执行 INSERT/UPDATE/DELETE 即可看到事件；Ctrl+C 退出）\n\n";

    // ── 2. 建立"从库"连接：复制协议握手 + COM_BINLOG_DUMP ─────────────────────
    $replica = BinlogConnection::connect(
        $config->getHost(),
        $config->getPort(),
        $config->getUser() ?? 'root',
        $config->getPassword() ?? '',
        REPLICA_SERVER_ID,
    );
    $replica->setupReplication();
    $replica->startDump($file, $pos);

    // ── 3. 事件循环：主库推送 → 解析 → 消费 ──────────────────────────────────
    $parser = new BinlogParser($columnNames);
    while (true) {
        printEvent($parser->parse($replica->readEvent()));
    }
})->await();

function printEvent(array $event): void
{
    if ($event['type'] === EventType::HEARTBEAT_LOG_EVENT) {
        return; // 心跳保活，不打印
    }

    $time = $event['timestamp'] > 0 ? \date('H:i:s', $event['timestamp']) : '        ';
    $line = sprintf('[%s] %s:%-7d %-16s', $time, $event['file'], $event['pos'], $event['name']);

    switch ($event['type']) {
        case EventType::ROTATE_EVENT:
            $line .= "切换到 {$event['next_file']}:{$event['next_pos']}";
            break;
        case EventType::FORMAT_DESCRIPTION_EVENT:
            $line .= "MySQL {$event['version']}, checksum={$event['checksum']}";
            break;
        case EventType::QUERY_EVENT:
            $line .= "db={$event['schema']}  {$event['sql']}";
            break;
        case EventType::XID_EVENT:
            $line .= "xid={$event['xid']}  (事务提交)";
            break;
        case EventType::GTID_LOG_EVENT:
        case EventType::ANONYMOUS_GTID_LOG_EVENT:
            $line .= $event['gtid'] ?? '(匿名事务, gtid_mode=OFF)';
            break;
        case EventType::TABLE_MAP_EVENT:
            $line .= sprintf('`%s`.`%s`  列: %s', $event['schema'], $event['table'], \implode(', ', $event['columns']));
            break;
        case EventType::WRITE_ROWS_EVENT_V1:
        case EventType::WRITE_ROWS_EVENT_V2:
        case EventType::UPDATE_ROWS_EVENT_V1:
        case EventType::UPDATE_ROWS_EVENT_V2:
        case EventType::DELETE_ROWS_EVENT_V1:
        case EventType::DELETE_ROWS_EVENT_V2:
            $line .= sprintf('`%s`.`%s`  %s ×%d', $event['schema'], $event['table'], $event['action'], \count($event['rows']));
            foreach ($event['rows'] as $row) {
                if ($event['action'] === 'update') {
                    $line .= "\n    - " . formatRow($row['before']) . "\n    + " . formatRow($row['after']);
                } else {
                    $line .= "\n    " . formatRow($row['after'] ?? $row['before']);
                }
            }
            break;
        default:
            // 其它事件仅展示类型与位点
            break;
    }

    echo $line, "\n";
}

function formatRow(?array $row): string
{
    if ($row === null) {
        return '(无)';
    }

    $pairs = [];
    foreach ($row as $column => $value) {
        if (\is_string($value) && !\mb_check_encoding($value, 'UTF-8')) {
            $value = '0x' . \strtoupper(\bin2hex($value)); // 二进制列值以 hex 展示
        }
        $pairs[] = $column . '=' . \var_export($value, true);
    }

    return '{' . \implode(', ', $pairs) . '}';
}
