<?php

declare(strict_types=1);

namespace Mogu\Binlog;

use RuntimeException;

/**
 * binlog 事件流解析器。
 *
 * 每个事件的原始字节布局：19 字节通用事件头 + 事件体（可能带尾部 CRC32）。
 * 解析 ROW 格式的事件需要先缓存 TABLE_MAP 事件（列类型/元数据），
 * 再按 binary-protocol 编码还原每一行的列值。
 *
 * @see https://dev.mysql.com/blog-archive/mysql-8-0-newly-redesigned-replication-protocol/
 */
final class BinlogParser
{
    private const HEADER_LEN = 19;

    /* MySQL 列类型码（TABLE_MAP / rows 事件中使用） */
    private const T_DECIMAL = 0x00;
    private const T_TINY = 0x01;
    private const T_SHORT = 0x02;
    private const T_LONG = 0x03;
    private const T_FLOAT = 0x04;
    private const T_DOUBLE = 0x05;
    private const T_NULL = 0x06;
    private const T_TIMESTAMP = 0x07;
    private const T_LONGLONG = 0x08;
    private const T_INT24 = 0x09;
    private const T_DATE = 0x0a;
    private const T_TIME = 0x0b;
    private const T_DATETIME = 0x0c;
    private const T_YEAR = 0x0d;
    private const T_NEWDATE = 0x0e;
    private const T_VARCHAR = 0x0f;
    private const T_BIT = 0x10;
    private const T_TIMESTAMP2 = 0x11;
    private const T_DATETIME2 = 0x12;
    private const T_TIME2 = 0x13;
    private const T_JSON = 0xf5;
    private const T_NEWDECIMAL = 0xf6;
    private const T_ENUM = 0xf7;
    private const T_SET = 0xf8;
    private const T_TINY_BLOB = 0xf9;
    private const T_MEDIUM_BLOB = 0xfa;
    private const T_LONG_BLOB = 0xfb;
    private const T_BLOB = 0xfc;
    private const T_VAR_STRING = 0xfd;
    private const T_STRING = 0xfe;
    private const T_GEOMETRY = 0xff;

    private const TYPE_NAMES = [
        self::T_DECIMAL => 'DECIMAL', self::T_TINY => 'TINY', self::T_SHORT => 'SHORT',
        self::T_LONG => 'LONG', self::T_FLOAT => 'FLOAT', self::T_DOUBLE => 'DOUBLE',
        self::T_NULL => 'NULL', self::T_TIMESTAMP => 'TIMESTAMP', self::T_LONGLONG => 'LONGLONG',
        self::T_INT24 => 'INT24', self::T_DATE => 'DATE', self::T_TIME => 'TIME',
        self::T_DATETIME => 'DATETIME', self::T_YEAR => 'YEAR', self::T_NEWDATE => 'NEWDATE',
        self::T_VARCHAR => 'VARCHAR', self::T_BIT => 'BIT', self::T_TIMESTAMP2 => 'TIMESTAMP',
        self::T_DATETIME2 => 'DATETIME', self::T_TIME2 => 'TIME', 0x14 => 'TYPED_ARRAY',
        self::T_JSON => 'JSON', self::T_NEWDECIMAL => 'NEWDECIMAL', self::T_ENUM => 'ENUM',
        self::T_SET => 'SET', self::T_TINY_BLOB => 'TINY_BLOB', self::T_MEDIUM_BLOB => 'MEDIUM_BLOB',
        self::T_LONG_BLOB => 'LONG_BLOB', self::T_BLOB => 'TEXT/BLOB', self::T_VAR_STRING => 'VARCHAR',
        self::T_STRING => 'CHAR', self::T_GEOMETRY => 'GEOMETRY',
    ];

    /** packed DECIMAL 中，余数位数字节数查表（MySQL my_decimal 打包规则） */
    private const DIGIT_BYTES = [0, 1, 1, 2, 2, 3, 3, 4, 4];

    /** @var array<int, array{schema:string, table:string, types:int[], meta:int[][]}> table_id => 列信息 */
    private array $tableMaps = [];

    private int $checksumAlg = 1; // 8.x 默认 CRC32；由 FORMAT_DESCRIPTION 事件确认

    /** @var array<string, string[]> 'schema.table'(小写) => 列名（可选，由外部注入） */
    private array $columnNames;

    public string $binlogFile = '';

    public int $binlogPos = 0;

    /**
     * @param array<string, string[]> $columnNames
     */
    public function __construct(array $columnNames = [])
    {
        $this->columnNames = \array_change_key_case($columnNames, \CASE_LOWER);
    }

    /**
     * 解析一个原始事件，返回描述数组（具体字段随事件类型不同）。
     *
     * @return array{type:int, name:string, timestamp:int, file:string, pos:int, server_id:int}
     */
    public function parse(string $raw): array
    {
        if (\strlen($raw) < self::HEADER_LEN) {
            throw new RuntimeException('事件长度小于通用事件头');
        }

        $timestamp = $this->readUint($raw, 0, 4);
        $type = \ord($raw[4]);
        $serverId = $this->readUint($raw, 5, 4);
        $eventSize = $this->readUint($raw, 9, 4);
        $logPos = $this->readUint($raw, 13, 4);

        $event = [
            'type' => $type,
            'name' => EventType::name($type),
            'timestamp' => $timestamp,
            'file' => $this->binlogFile,
            'pos' => $logPos,
            'server_id' => $serverId,
        ];

        // 剥掉尾部 CRC32（ROTATE / FORMAT_DESCRIPTION 自身也带）
        $body = $raw;
        if ($this->checksumAlg !== 0 && \strlen($raw) >= $eventSize && $eventSize >= 4) {
            $body = \substr($raw, 0, $eventSize - 4);
        }

        $off = self::HEADER_LEN;

        switch ($type) {
            case EventType::FORMAT_DESCRIPTION_EVENT:
                $event += $this->parseFormatDescription($body, $off);
                break;

            case EventType::ROTATE_EVENT:
                $nextFile = \rtrim(\substr($body, $off + 8), "\x00");
                $nextPos = $this->readUint($body, $off, 8);
                $this->binlogFile = $nextFile;
                $this->binlogPos = $nextPos;
                $event['next_file'] = $nextFile;
                $event['next_pos'] = $nextPos;
                $event['file'] = $nextFile;
                $event['pos'] = $nextPos;
                break;

            case EventType::QUERY_EVENT:
                $event += $this->parseQuery($body, $off);
                break;

            case EventType::XID_EVENT:
                $event['xid'] = $this->readUint($body, $off, 8);
                break;

            case EventType::GTID_LOG_EVENT:
            case EventType::ANONYMOUS_GTID_LOG_EVENT:
                $event['gtid'] = $this->parseGtid($body, $off, $type === EventType::GTID_LOG_EVENT);
                break;

            case EventType::TABLE_MAP_EVENT:
                $event += $this->parseTableMap($body, $off);
                break;

            case EventType::WRITE_ROWS_EVENT_V1:
            case EventType::WRITE_ROWS_EVENT_V2:
            case EventType::UPDATE_ROWS_EVENT_V1:
            case EventType::UPDATE_ROWS_EVENT_V2:
            case EventType::DELETE_ROWS_EVENT_V1:
            case EventType::DELETE_ROWS_EVENT_V2:
                $event += $this->parseRows($type, $body, $off);
                break;

            case EventType::ROWS_QUERY_LOG_EVENT:
                $event['query'] = \ltrim(\substr($body, $off + 1), "\x00"); // [len][sql]
                break;

            default:
                // 其余事件（HEARTBEAT / PREVIOUS_GTIDS / STOP …）保持通用字段
                break;
        }

        if ($logPos > 0) {
            $this->binlogPos = $logPos;
        }

        return $event;
    }

    /* ------------------------------ 各事件解析 ------------------------------ */

    private function parseFormatDescription(string $body, int $off): array
    {
        $off += 2; // binlog-version（固定 4）
        $version = $this->readCString($body, $off); // server version，null 结尾
        $off += 4; // create timestamp

        $headerLen = \ord($body[$off++]);

        // body 已经剥掉 CRC32，所以末尾 1 字节就是 checksum 算法（0=OFF 1=CRC32）
        $alg = \ord($body[\strlen($body) - 1]);
        $this->checksumAlg = $alg;

        // 之后是各事件类型的 post-header 长度表；TABLE_MAP / ROWS 的 table_id
        // 在 4.1+ 协议中固定 6 字节，行事件 v1/v2 由事件类型码本身区分，无需此表

        return ['version' => $version, 'header_len' => $headerLen, 'checksum' => $alg === 0 ? 'OFF' : 'CRC32'];
    }

    private function readCString(string $data, int &$offset): string
    {
        $end = \strpos($data, "\x00", $offset);
        if ($end === false) {
            $string = \substr($data, $offset);
            $offset = \strlen($data);
            return $string;
        }
        $string = \substr($data, $offset, $end - $offset);
        $offset = $end + 1;
        return $string;
    }

    private function parseQuery(string $body, int $off): array
    {
        $off += 4 + 4; // thread_id + exec_time
        $schemaLen = \ord($body[$off++]);
        $off += 2; // error_code
        $statusLen = $this->readUint($body, $off, 2);
        $off += 2 + $statusLen;

        $schema = \substr($body, $off, $schemaLen);
        $off += $schemaLen + 1; // 末尾 \0

        return ['schema' => $schema, 'sql' => \substr($body, $off)];
    }

    private function parseGtid(string $body, int $off, bool $hasGtid): ?string
    {
        $off += 1; // flags

        if (!$hasGtid) { // ANONYMOUS_GTID（gtid_mode=OFF 时的占位）
            return null;
        }

        $sid = \bin2hex(\substr($body, $off, 16));
        $off += 16;
        $gno = $this->readUint($body, $off, 8);

        $uuid = \substr($sid, 0, 8) . '-' . \substr($sid, 8, 4) . '-' . \substr($sid, 12, 4)
            . '-' . \substr($sid, 16, 4) . '-' . \substr($sid, 20, 12);

        return "{$uuid}:{$gno}";
    }

    private function parseTableMap(string $body, int $off): array
    {
        $tableId = $this->readUint($body, $off, 6); // table_id 固定 6 字节（4.1+ 协议）
        $off += 6 + 2; // + flags

        $schemaLen = \ord($body[$off++]);
        $schema = \substr($body, $off, $schemaLen);
        $off += $schemaLen + 1;
        $tableLen = \ord($body[$off++]);
        $table = \substr($body, $off, $tableLen);
        $off += $tableLen + 1;

        $columnCount = $this->readLenenc($body, $off);
        $types = [];
        for ($i = 0; $i < $columnCount; ++$i) {
            $types[] = \ord($body[$off + $i]);
        }
        $off += $columnCount;

        $metaLen = $this->readLenenc($body, $off);
        $metaBlock = \substr($body, $off, $metaLen);
        $off += $metaLen;

        // 按类型从 metadata 块切出每列元数据
        $meta = [];
        $moff = 0;
        foreach ($types as $t) {
            $len = match ($t) {
                self::T_FLOAT, self::T_DOUBLE, self::T_BLOB, self::T_GEOMETRY, self::T_JSON,
                self::T_TIMESTAMP2, self::T_DATETIME2, self::T_TIME2,
                self::T_ENUM, self::T_SET => 1,
                self::T_VARCHAR, self::T_VAR_STRING, self::T_BIT,
                self::T_NEWDECIMAL, self::T_DECIMAL, self::T_STRING => 2,
                default => 0,
            };
            $meta[] = $len > 0 ? \array_values(\unpack('C*', \substr($metaBlock, $moff, $len))) : [];
            $moff += $len;
        }

        // NULL 位图（列可空性），其后 8.0 还有 optional metadata（binlog_row_metadata=FULL 时含列名，此处从 information_schema 获取）
        $this->tableMaps[$tableId] = ['schema' => $schema, 'table' => $table, 'types' => $types, 'meta' => $meta];

        return [
            'table_id' => $tableId,
            'schema' => $schema,
            'table' => $table,
            'columns' => \array_map(
                static fn (int $t): string => self::TYPE_NAMES[$t] ?? sprintf('0x%02x', $t),
                $types,
            ),
        ];
    }

    private function parseRows(int $type, string $body, int $off): array
    {
        $tableId = $this->readUint($body, $off, 6); // table_id 固定 6 字节（4.1+ 协议）
        $off += 6 + 2; // + flags

        $map = $this->tableMaps[$tableId] ?? null;
        $schema = $map['schema'] ?? '?';
        $table = $map['table'] ?? '?';
        $types = $map['types'] ?? [];
        $meta = $map['meta'] ?? [];
        $columns = $this->resolveColumnNames($schema, $table, \count($types));

        // v2 行事件（0x1e/0x1f/0x20）：flags 后是 extra_data_len(2，含自身)；
        // MySQL 8.4+ 在 extra_data 之后、present bitmap 之前还带显式列数（lenenc），
        // 位图长度以该列数为准（部分列镜像时会小于 TABLE_MAP 的表列数）
        $columnCount = \count($types);
        if (\in_array($type, [EventType::WRITE_ROWS_EVENT_V2, EventType::UPDATE_ROWS_EVENT_V2, EventType::DELETE_ROWS_EVENT_V2], true)) {
            $extraLen = $this->readUint($body, $off, 2);
            $off += $extraLen;
            $columnCount = $this->readLenenc($body, $off);
        }
        $bitmapLen = intdiv($columnCount + 7, 8);

        $isUpdate = $type === EventType::UPDATE_ROWS_EVENT_V1 || $type === EventType::UPDATE_ROWS_EVENT_V2;
        $action = match (true) {
            $isUpdate => 'update',
            $type === EventType::DELETE_ROWS_EVENT_V1, $type === EventType::DELETE_ROWS_EVENT_V2 => 'delete',
            default => 'insert',
        };

        $present1 = \substr($body, $off, $bitmapLen);
        $off += $bitmapLen;
        $present2 = null;
        if ($isUpdate) {
            $present2 = \substr($body, $off, $bitmapLen);
            $off += $bitmapLen;
        }

        $rows = [];
        $rowBitmapLen = intdiv($columnCount + 7, 8);
        while ($off + $rowBitmapLen <= \strlen($body)) {
            $row = ['before' => null, 'after' => null];

            try {
                if ($action === 'update' || $action === 'delete') {
                    $row['before'] = $this->decodeRow($body, $off, $types, $meta, $columns, $present1, $rowBitmapLen);
                }
                if ($action === 'update') {
                    $row['after'] = $this->decodeRow($body, $off, $types, $meta, $columns, $present2, $rowBitmapLen);
                }
                if ($action === 'insert') {
                    $row['after'] = $this->decodeRow($body, $off, $types, $meta, $columns, $present1, $rowBitmapLen);
                }
            } catch (RuntimeException $e) {
                // 解码失败（表结构信息缺失/类型不支持）：停止本事件解析，避免连锁错位
                if (\getenv('BINLOG_DEBUG')) {
                    \fwrite(\STDERR, '[decodeRow] ' . $e->getMessage() . "\n");
                }
                break;
            }

            $rows[] = $row;
        }

        return [
            'table_id' => $tableId,
            'schema' => $schema,
            'table' => $table,
            'action' => $action,
            'rows' => $rows,
        ];
    }

    /* ------------------------------ 行解码 ------------------------------ */

    private function decodeRow(
        string $body,
        int &$off,
        array $types,
        array $meta,
        array $columns,
        string $present,
        int $bitmapLen,
    ): array {
        $nullBitmap = \substr($body, $off, $bitmapLen);
        $off += $bitmapLen;

        $values = [];
        foreach ($types as $i => $type) {
            if (!self::bitSet($present, $i)) {
                continue; // 列不在本镜像中（binlog_row_image=MINIMAL 时会出现）
            }
            $key = $columns[$i];
            if (self::bitSet($nullBitmap, $i)) {
                $values[$key] = null;
                continue;
            }
            try {
                $values[$key] = $this->decodeValue($body, $off, $type, $meta[$i] ?? []);
            } catch (RuntimeException $e) {
                throw new RuntimeException(sprintf('第 %d 列(%s)解码失败: %s', $i + 1, self::TYPE_NAMES[$type] ?? sprintf('0x%02x', $type), $e->getMessage()));
            }
        }

        return $values;
    }

    private function decodeValue(string $body, int &$off, int $type, array $meta): mixed
    {
        switch ($type) {
            case self::T_TINY:
                return $this->readInt($body, $off, 1);
            case self::T_SHORT:
                return $this->readInt($body, $off, 2);
            case self::T_INT24:
                return $this->readInt($body, $off, 3);
            case self::T_LONG:
                return $this->readInt($body, $off, 4);
            case self::T_LONGLONG:
                return $this->readInt($body, $off, 8);
            case self::T_FLOAT:
                $value = \unpack('f', \substr($body, ($off += 4) - 4, 4))[1];
                return \round($value, 4);
            case self::T_DOUBLE:
                return \unpack('d', \substr($body, ($off += 8) - 8, 8))[1];
            case self::T_NEWDECIMAL:
            case self::T_DECIMAL:
                return $this->readDecimal($body, $off, $meta[0] ?? 10, $meta[1] ?? 0);
            case self::T_VARCHAR:
            case self::T_VAR_STRING:
                // 长度前缀：meta（最大字节数）>=256 时是 2 字节 LE，否则 1 字节（非通用 lenenc！）
                return $this->readVarString($body, $off, ($meta[0] ?? 0) | (($meta[1] ?? 0) << 8));
            case self::T_STRING: // 旧式 CHAR；metadata[0] 是 real type
                if (\in_array($meta[0] ?? 0, [self::T_ENUM, self::T_SET], true)) {
                    $width = \max(1, $meta[1] ?? 1);
                    $value = $this->readUint($body, $off, $width);
                    $off += $width;
                    return $value;
                }
                return $this->readVarString($body, $off, ($meta[0] ?? 0) | (($meta[1] ?? 0) << 8));
            case self::T_ENUM:
            case self::T_SET:
                $width = ($meta[0] ?? 0) + 1;
                $value = $this->readUint($body, $off, $width);
                $off += $width;
                return $value; // 索引/位掩码，名称需查表结构
            case self::T_BIT:
                $bytes = $meta[1] ?? 1;
                $bits = $meta[0] ?? 8;
                $value = $this->readUint($body, $off, $bytes);
                $off += $bytes;
                return $value << \max(0, $bits - $bytes * 8);
            case self::T_BLOB:
            case self::T_TINY_BLOB:
            case self::T_MEDIUM_BLOB:
            case self::T_LONG_BLOB:
            case self::T_GEOMETRY:
            case self::T_JSON:
                $lenBytes = \max(1, $meta[0] ?? 4);
                $len = $this->readUint($body, $off, $lenBytes);
                $off += $lenBytes;
                if ($off + $len > \strlen($body)) {
                    throw new RuntimeException('BLOB/JSON 越界读取');
                }
                $data = \substr($body, $off, $len);
                $off += $len;
                if ($type === self::T_JSON) {
                    return '<json:' . \strlen($data) . ' bytes>'; // JSON binary 格式，可按需扩展解码
                }
                return $type === self::T_GEOMETRY ? '<geometry:' . \strlen($data) . ' bytes>' : $data;
            case self::T_TIMESTAMP:
                $seconds = $this->readUint($body, $off, 4);
                $off += 4;
                return \date('Y-m-d H:i:s', $seconds);
            case self::T_TIMESTAMP2:
                $seconds = $this->readUintBe($body, $off, 4);
                $frac = $this->readFraction($body, $off, $meta[0] ?? 0);
                return \date('Y-m-d H:i:s', $seconds) . $frac;
            case self::T_DATETIME: // int64 LE：YYYYMMDDHHMMSS
                $packed = $this->readInt($body, $off, 8);
                $s = (string) $packed;
                return \substr($s, 0, 4) . '-' . \substr($s, 4, 2) . '-' . \substr($s, 6, 2) . ' '
                    . \substr($s, 8, 2) . ':' . \substr($s, 10, 2) . ':' . \substr($s, 12, 2);
            case self::T_DATETIME2: // 40 位大端位域 + 小数秒
                $v = $this->readUintBe($body, $off, 5) - 0x8000000000;
                $yearMonth = $v >> 22;
                $frac = $this->readFraction($body, $off, $meta[0] ?? 0);
                return sprintf(
                    '%04d-%02d-%02d %02d:%02d:%02d%s',
                    intdiv($yearMonth, 13),
                    $yearMonth % 13,
                    ($v >> 17) & 0x1f,
                    ($v >> 12) & 0x1f,
                    ($v >> 6) & 0x3f,
                    $v & 0x3f,
                    $frac,
                );
            case self::T_TIME: // int24 LE：H*10000+M*100+S
                $packed = $this->readUint($body, $off, 3);
                $off += 3;
                return sprintf('%02d:%02d:%02d', intdiv($packed, 10000), intdiv($packed, 100) % 100, $packed % 100);
            case self::T_TIME2:
                $v = $this->readUintBe($body, $off, 3) - 0x800000; // 1 sign + 10h + 6m + 6s
                $frac = $this->readFraction($body, $off, $meta[0] ?? 0);
                return sprintf('%02d:%02d:%02d%s', ($v >> 12) & 0x3ff, ($v >> 6) & 0x3f, $v & 0x3f, $frac);
            case self::T_DATE:
                $v = $this->readUint($body, $off, 3);
                $off += 3;
                return sprintf('%04d-%02d-%02d', $v >> 9, ($v >> 5) & 0x0f, $v & 0x1f);
            case self::T_YEAR:
                $v = \ord($body[$off++]);
                return $v === 0 ? '0000' : (string) (1900 + $v);
            case self::T_NULL:
                return null;
            default:
                $rest = \substr($body, $off);
                $off = \strlen($body);
                return '<unknown type 0x' . \dechex($type) . ': ' . \bin2hex(\substr($rest, 0, 32)) . '…>';
        }
    }

    /* ------------------------------ 底层读数 ------------------------------ */

    /** 小端有符号整数（binlog 中整数均为有符号） */
    private function readInt(string $data, int &$off, int $bytes): int
    {
        $value = $this->readUint($data, $off, $bytes);
        $off += $bytes;
        $signBit = 1 << ($bytes * 8 - 1);
        return $value >= $signBit ? $value - ($signBit << 1) : $value;
    }

    private function readUint(string $data, int $off, int $bytes): int
    {
        if ($off < 0 || $off + $bytes > \strlen($data)) {
            throw new RuntimeException('uint 越界读取');
        }
        $value = 0;
        for ($i = $bytes - 1; $i >= 0; --$i) { // little-endian
            $value = ($value << 8) | \ord($data[$off + $i]);
        }

        return $value;
    }

    private function readUintBe(string $data, int &$off, int $bytes): int
    {
        if ($off < 0 || $off + $bytes > \strlen($data)) {
            throw new RuntimeException('uint-be 越界读取');
        }
        $value = 0;
        for ($i = 0; $i < $bytes; ++$i) { // big-endian
            $value = ($value << 8) | \ord($data[$off + $i]);
        }
        $off += $bytes;

        return $value;
    }

    private function readFraction(string $data, int &$off, int $fsp): string
    {
        if ($fsp <= 0) {
            return '';
        }
        $bytes = intdiv($fsp + 1, 2); // fsp 1-2 => 1 byte … 5-6 => 3 bytes
        $value = $this->readUintBe($data, $off, $bytes);
        $value = intdiv($value, 10 ** (2 * $bytes - $fsp)); // 低位多余的一位是字节对齐填充

        return '.' . \str_pad((string) $value, $fsp, '0', \STR_PAD_LEFT);
    }

    private function readLenenc(string $data, int &$off): int
    {
        if ($off < 0 || $off >= \strlen($data)) {
            throw new RuntimeException('lenenc 越界读取');
        }
        $first = \ord($data[$off++]);
        if ($first < 0xfb) {
            return $first;
        }

        $len = match ($first) {
            0xfc => 2,
            0xfd => 3,
            default => 8,
        };
        $value = $this->readUint($data, $off, $len);
        $off += $len;

        return $value;
    }

    /**
     * VARCHAR/VARSTRING 值：长度前缀不是通用 lenenc，而是固定宽度整数——
     * meta（列最大字节数）>=256 时 2 字节 LE，否则 1 字节。
     */
    private function readVarString(string $data, int &$off, int $maxBytes): string
    {
        $len = $maxBytes >= 256 ? $this->readUint($data, $off, 2) : \ord($data[$off] ?? '');
        if ($off < 0 || $off + $len > \strlen($data)) {
            throw new RuntimeException('VARCHAR 越界读取');
        }
        $off += $maxBytes >= 256 ? 2 : 1;
        $value = \substr($data, $off, $len);
        $off += $len;

        return $value;
    }

    /** packed DECIMAL（原码存储：每 9 位数字 4 字节大端，最高位是符号位；负数整体按位取反） */
    private function readDecimal(string $data, int &$off, int $precision, int $scale): string
    {
        $integral = $precision - $scale;
        $bytesPerDigits = static fn (int $digits): int => intdiv($digits, 9) * 4 + self::DIGIT_BYTES[$digits % 9];

        $size = $bytesPerDigits($integral) + $bytesPerDigits($scale);
        $raw = \substr($data, $off, $size);
        $off += $size;

        $negative = (\ord($raw[0]) & 0x80) === 0;
        if ($negative) {
            $raw = ~$raw; // 负数存储为正数表示的按位取反
        }
        $raw[0] = \chr(\ord($raw[0]) & 0x7f); // 剥离首组的符号位

        $pos = 0;
        $intPart = $this->readDecimalGroups($raw, $integral, $pos);
        $fracPart = $scale > 0 ? $this->readDecimalGroups($raw, $scale, $pos) : '';

        $intPart = \ltrim($intPart, '0') ?: '0';

        return ($negative ? '-' : '') . $intPart . ($fracPart !== '' ? '.' . $fracPart : '');
    }

    /** 读取 packed DECIMAL 中连续的 $digitCount 位数字（$pos 按引用推进） */
    private function readDecimalGroups(string $raw, int $digitCount, int &$pos): string
    {
        $digits = '';
        $groups = intdiv($digitCount, 9);
        $remainder = $digitCount % 9;
        for ($g = 0; $g < $groups; ++$g, $pos += 4) {
            $digits .= \str_pad((string) \unpack('N', \substr($raw, $pos, 4))[1], 9, '0', \STR_PAD_LEFT);
        }
        if ($remainder > 0) {
            $b = self::DIGIT_BYTES[$remainder];
            $value = \unpack('N', \str_pad(\substr($raw, $pos, $b), 4, "\x00", \STR_PAD_LEFT))[1];
            $digits .= \str_pad((string) $value, $remainder, '0', \STR_PAD_LEFT);
            $pos += $b;
        }

        return $digits;
    }

    private static function bitSet(string $bitmap, int $bit): bool
    {
        $byte = $bit >> 3;
        return $byte < \strlen($bitmap) && (\ord($bitmap[$byte]) & (1 << ($bit & 7))) !== 0;
    }

    /** @return string[] 列名（优先 information_schema 注入的，否则 col_0 …） */
    private function resolveColumnNames(string $schema, string $table, int $count): array
    {
        $names = $this->columnNames[\strtolower($schema . '.' . $table)] ?? [];
        $result = [];
        for ($i = 0; $i < $count; ++$i) {
            $result[] = $names[$i] ?? "col_{$i}";
        }

        return $result;
    }
}
