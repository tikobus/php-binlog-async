<?php

declare(strict_types=1);

namespace Tikobus\PhpBinlogAsync;

use Amp\Socket;
use RuntimeException;

/**
 * MySQL 复制协议客户端：把当前进程伪装成一个"从库"（replica）。
 *
 * amphp/mysql 只实现了查询协议（text / binary protocol），不支持复制协议，
 * 因此这里直接基于 amphp/socket 手写：
 *
 *  1. TCP 连接 + 普通握手认证（caching_sha2_password / mysql_native_password）
 *  2. SET @master_binlog_checksum= @@global.binlog_checksum
 *     （不设置的话，主库推送带 CRC32 的 FORMAT_DESCRIPTION 事件后会直接报错断开）
 *  3. COM_BINLOG_DUMP（携带唯一 server-id + binlog 文件名 + 位点）
 *  4. 此后主库在这条连接上持续推送 binlog 事件流（每个事件一个 MySQL packet，
 *     seq id 对每个事件从 0 重新开始；超过 16MB 的事件会拆成多个 packet）
 *
 * 账号需要 REPLICATION SLAVE 权限：GRANT REPLICATION SLAVE ON *.* TO user@'%';
 *
 * @see https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__binlog__dump.html
 */
final class BinlogConnection
{
    private const MAX_PACKET = 0xffffff;

    // 客户端能力位（只声明握手/认证所需，不开 SSL、压缩、DEPRECATE_EOF）
    private const CLIENT_LONG_PASSWORD = 0x00000001;
    private const CLIENT_LONG_FLAG = 0x00000004;
    private const CLIENT_PROTOCOL_41 = 0x00000200;
    private const CLIENT_TRANSACTIONS = 0x00002000;
    private const CLIENT_SECURE_CONNECTION = 0x00008000;
    private const CLIENT_PLUGIN_AUTH = 0x00080000;

    private const OK = 0x00;
    private const EXTRA_AUTH = 0x01;
    private const AUTH_SWITCH = 0xfe;
    private const ERR = 0xff;

    private Socket\Socket $socket;

    private string $buffer = '';

    private int $lastSeq = 0; // 最近收到的 packet seq id，响应类包必须接续它

    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $user,
        private readonly string $password,
        private readonly int $serverId, // 伪装从库的唯一 server-id（不能与主库相同）
    ) {
    }

    public static function connect(string $host, int $port, string $user, string $password, int $serverId): self
    {
        $socket = Socket\connect("tcp://{$host}:{$port}");
        $self = new self($host, $port, $user, $password, $serverId);
        $self->socket = $socket;
        $self->handshake();
        return $self;
    }

    public function close(): void
    {
        $this->socket->close();
    }

    /* ------------------------- 复制订阅 ------------------------- */

    /**
     * 订阅前设置会话变量。必须在 COM_BINLOG_DUMP 之前执行。
     */
    public function setupReplication(): void
    {
        // 8.0 及之前叫 @master_binlog_checksum，8.4+ 改叫 @source_binlog_checksum（用户变量，设置无效也不会报错，两个都设兼容所有版本）
        $this->query('SET @master_binlog_checksum= @@global.binlog_checksum');
        $this->query('SET @source_binlog_checksum= @@global.binlog_checksum');
        // 心跳周期（纳秒）：主库在无事件时按该周期发 HEARTBEAT_LOG_EVENT，防止连接空闲超时
        $this->query('SET @master_heartbeat_period= 1500000000');
    }

    /**
     * COM_BINLOG_DUMP：请求主库从 (file, pos) 开始推送 binlog 事件。
     * 调用后当前连接进入"从库"角色，不再接受普通查询。
     */
    public function startDump(string $file, int $pos): void
    {
        // [cmd 0x12][pos 4LE][flags 4LE][server_id 4LE][binlog filename]
        // flags=0：阻塞模式，没有新事件时主库挂起推送（正是订阅语义）
        $this->writePacket("\x12" . \pack('V3', $pos, 0, $this->serverId) . $file);
    }

    /**
     * 读取下一个 binlog 事件（含 19 字节事件头，含尾部 CRC32）。
     * 连接被主库断开或返回 ERR 时抛异常。
     */
    public function readEvent(): string
    {
        $packet = $this->readPacket();

        if (\getenv('BINLOG_DEBUG')) {
            \fprintf(\STDERR, "dump-packet seq=%d len=%d hex=%s\n", $this->lastSeq, \strlen($packet), \bin2hex(\substr($packet, 0, 32)));
        }

        if ($packet === '' || \ord($packet[0]) === self::ERR) {
            throw new RuntimeException('主库返回错误: ' . $this->formatError($packet));
        }

        // dump 流中每个 packet 的 payload 首字节是 OK 标志 0x00，其后才是事件字节
        $payload = \substr($packet, 1);

        // 事件可能超过 16MB 而被拆成多个 packet，按事件头里声明的 event_size 拼齐
        if (\strlen($payload) >= 19) {
            $eventSize = $this->unpackUint(\substr($payload, 9, 4));
            while (\strlen($payload) < $eventSize) {
                $more = $this->readPacket();
                if (\ord($more[0]) === self::ERR) {
                    throw new RuntimeException('主库返回错误: ' . $this->formatError($more));
                }
                $payload .= \substr($more, 1); // 后续分片同样跳过 OK 标志字节
            }
        }

        return $payload;
    }

    /* ------------------------- 普通查询（订阅前可用） ------------------------- */

    /**
     * 执行文本协议 SQL，返回结果行（每行为字符串数组；SHOW / SET 场景够用）。
     */
    public function query(string $sql): array
    {
        $this->writePacket("\x03" . $sql);
        $payload = $this->readPacket();
        $this->assertOk($payload);

        if (\ord($payload[0]) === self::OK) {
            return []; // 无结果集（SET / USE 等）
        }

        // 首包为结果集：lenenc 列数 → 列定义 ×N → EOF → 行 ×N → EOF
        $offset = 0;
        $this->readLenencInt($payload, $offset); // column count（逐列读取时直接跳过列定义 packet）

        while (($column = $this->readPacket())[0] !== "\xfe" || \strlen($column) > 8) {
        }

        $rows = [];
        for (;;) {
            $row = $this->readPacket();
            if ($row[0] === "\xfe" && \strlen($row) <= 8) {
                break;
            }
            $offset = 0;
            $values = [];
            while ($offset < \strlen($row)) {
                if (\ord($row[$offset]) === 0xfb) { // NULL
                    $values[] = null;
                    ++$offset;
                    continue;
                }
                $values[] = $this->readLenencString($row, $offset);
            }
            $rows[] = $values;
        }

        return $rows;
    }

    /* ------------------------- 握手与认证 ------------------------- */

    private function handshake(): void
    {
        $greeting = $this->readPacket();
        $offset = 0;

        $protocolVersion = \ord($greeting[$offset++]);
        if ($protocolVersion !== 10) {
            throw new RuntimeException("不支持的协议版本: {$protocolVersion}");
        }

        $this->readNullString($greeting, $offset); // server version
        $offset += 4; // thread id
        $nonce = \substr($greeting, $offset, 8); // auth-plugin-data-part-1
        $offset += 8 + 1; // filler
        $offset += 2; // capability flags (lower)
        $offset += 1; // charset
        $offset += 2; // status flags
        $authDataLen = \ord($greeting[$offset + 2]) ?: 0; // capability upper 在前 2 字节，这里指向 auth_plugin_data_len
        $offset += 2 + 1 + 10; // capability upper + auth data len + reserved
        $part2 = \substr($greeting, $offset, \max(13, $authDataLen - 8) - 1);
        $nonce .= $part2;
        $offset += \strlen($part2) + 1;
        $plugin = $this->readNullString($greeting, $offset) ?: 'mysql_native_password';

        // HandshakeResponse41
        $capabilities = self::CLIENT_LONG_PASSWORD | self::CLIENT_LONG_FLAG | self::CLIENT_PROTOCOL_41
            | self::CLIENT_TRANSACTIONS | self::CLIENT_SECURE_CONNECTION | self::CLIENT_PLUGIN_AUTH;

        $response = \pack('VV', $capabilities, 1 << 24) // caps + max_packet_size
            . "\x21" . \str_repeat("\x00", 23) // charset=utf8_general_ci + reserved
            . $this->user . "\x00"
            . \chr(\strlen($this->authResponse($plugin, $nonce)))
            . $this->authResponse($plugin, $nonce)
            . $plugin . "\x00"; // 未声明 CLIENT_CONNECT_WITH_DB，不发送 database 字段

        $this->writePacket($response, $this->lastSeq + 1); // 握手响应 seq 接续 greeting
        $this->finishAuth($plugin, $nonce);
    }

    /**
     * 处理认证后续交互（OK / ERR / AuthSwitchRequest / caching_sha2 的 more-data）。
     */
    private function finishAuth(string $plugin, string $nonce): void
    {
        for (;;) {
            $payload = $this->readPacket();
            $head = \ord($payload[0]);

            if ($head === self::OK) {
                return; // 认证完成
            }
            if ($head === self::ERR) {
                throw new RuntimeException('认证失败: ' . $this->formatError($payload));
            }
            if ($head === self::AUTH_SWITCH) {
                // 服务器要求换认证插件：[fe][plugin name \0][nonce]
                $offset = 1;
                $plugin = $this->readNullString($payload, $offset);
                $nonce = \rtrim(\substr($payload, $offset), "\x00");
                $this->writePacket($this->authResponse($plugin, $nonce), $this->lastSeq + 1);
                continue;
            }
            if ($head === self::EXTRA_AUTH) {
                $this->handleCachingSha2(substr($payload, 1), $nonce);
                continue;
            }

            throw new RuntimeException(sprintf('认证过程中收到未知 packet: 0x%02x', $head));
        }
    }

    /**
     * caching_sha2_password 的 full auth：非 SSL 连接需要向服务器要 RSA 公钥，
     * 用公钥加密 (password XOR nonce) 后发送。fast path 直接等到 OK。
     */
    private function handleCachingSha2(string $data, string $nonce): void
    {
        $step = \ord($data[0]);

        if ($step === 0x03) { // fast auth 成功，下一个 packet 是 OK
            return;
        }
        if ($step !== 0x04) { // 0x04 = full auth
            throw new RuntimeException(sprintf('caching_sha2_password 未知步骤: 0x%02x', $step));
        }

        $this->writePacket("\x02", $this->lastSeq + 1); // 请求 RSA 公钥
        $payload = $this->readPacket();
        if (\ord($payload[0]) !== self::EXTRA_AUTH) {
            throw new RuntimeException('请求 RSA 公钥失败');
        }

        $publicKey = "-----BEGIN PUBLIC KEY-----\n"
            . \chunk_split(\base64_encode(\substr($payload, 2)), 64)
            . "-----END PUBLIC KEY-----\n";

        $xor = $this->password ^ \str_pad($nonce, \strlen($this->password), $nonce);
        if (!\openssl_public_encrypt($xor, $encrypted, $publicKey, \OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA 加密密码失败: ' . \openssl_error_string());
        }

        $this->writePacket($encrypted, $this->lastSeq + 1);
    }

    private function authResponse(string $plugin, string $nonce): string
    {
        if ($this->password === '') {
            return '';
        }

        return match ($plugin) {
            'mysql_native_password' => self::nativeScramble($this->password, $nonce),
            'caching_sha2_password', 'sha256_password' => self::sha256Scramble($this->password, $nonce),
            default => throw new RuntimeException("不支持的认证插件: {$plugin}"),
        };
    }

    private static function nativeScramble(string $password, string $nonce): string
    {
        $stage1 = \sha1($password, true);
        $stage2 = \sha1($stage1, true);
        $token = \sha1($nonce . $stage2, true);
        return $stage1 ^ $token;
    }

    private static function sha256Scramble(string $password, string $nonce): string
    {
        $digest1 = \hash('sha256', $password, true);
        $digest2 = \hash('sha256', $digest1, true);
        $digest3 = \hash('sha256', $digest2 . $nonce, true);
        return $digest1 ^ $digest3;
    }

    /* ------------------------- MySQL packet I/O ------------------------- */

    private function readPacket(): string
    {
        $payload = '';
        do {
            $header = $this->readBytes(4);
            $length = $this->unpackUint(\substr($header, 0, 3));
            $this->lastSeq = \ord($header[3]);
            $payload .= $this->readBytes($length);
        } while ($length === self::MAX_PACKET); // 0xffffff 表示还有后续分片

        return $payload;
    }

    private function writePacket(string $payload, int $seqId = 0): void
    {
        while ($payload !== '') {
            $chunk = \substr($payload, 0, self::MAX_PACKET);
            $payload = \substr($payload, \strlen($chunk));
            $this->socket->write(\substr(\pack('V', \strlen($chunk)), 0, 3) . \chr($seqId++) . $chunk);

            if ($payload === '' && \strlen($chunk) === self::MAX_PACKET) {
                // payload 恰好为 16MB 整数倍：按协议补一个空包终结
                $this->socket->write("\x00\x00\x00" . \chr($seqId));
            }
        }
    }

    private function readBytes(int $length): string
    {
        while (\strlen($this->buffer) < $length) {
            $chunk = $this->socket->read();
            if ($chunk === null) {
                throw new RuntimeException('连接被主库关闭');
            }
            $this->buffer .= $chunk;
        }

        $data = \substr($this->buffer, 0, $length);
        $this->buffer = \substr($this->buffer, $length);
        return $data;
    }

    private function assertOk(string $payload): void
    {
        $head = \ord($payload[0]);
        if ($head === self::ERR) {
            throw new RuntimeException('SQL 执行失败: ' . $this->formatError($payload));
        }
    }

    private function formatError(string $payload): string
    {
        if (\strlen($payload) < 3) {
            return '(连接已关闭)';
        }
        $errno = \unpack('v', \substr($payload, 1, 2))[1];
        // [ff][errno 2][#][sqlstate 5] message
        $message = \substr($payload, \ord($payload[3] ?? '') === 0x23 ? 9 : 3);
        return "({$errno}) {$message}";
    }

    private function readNullString(string $data, int &$offset): string
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

    private function readLenencInt(string $data, int &$offset): int
    {
        $first = \ord($data[$offset++]);
        return match (true) {
            $first < 0xfb => $first,
            $first === 0xfc => $this->unpackUint(\substr($data, ($offset += 2) - 2, 2)),
            $first === 0xfd => $this->unpackUint(\substr($data, ($offset += 3) - 3, 3)),
            default => $this->unpackUint64(\substr($data, ($offset += 8) - 8, 8)),
        };
    }

    private function readLenencString(string $data, int &$offset): string
    {
        $length = $this->readLenencInt($data, $offset);
        $string = \substr($data, $offset, $length);
        $offset += $length;
        return $string;
    }

    private function unpackUint(string $bytes): int
    {
        $result = 0;
        foreach (\array_reverse(\str_split($bytes)) as $byte) { // little-endian
            $result = ($result << 8) | \ord($byte);
        }
        return $result;
    }

    private function unpackUint64(string $bytes): int
    {
        $value = \unpack('P', $bytes)[1]; // little-endian 64 位
        return $value > 0x7fffffffffffffff ? $value - (1 << 63) * 2 : $value;
    }
}
