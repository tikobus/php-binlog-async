<?php

declare(strict_types=1);

namespace Mogu\Binlog;

/**
 * binlog 事件类型码（event header 第 5 字节 type_code 的取值）。
 *
 * @see https://dev.mysql.com/doc/refman/8.4/en/binlog-event-type.html
 */
final class EventType
{
    public const UNKNOWN_EVENT = 0x00;
    public const START_EVENT_V3 = 0x01;
    public const QUERY_EVENT = 0x02;
    public const STOP_EVENT = 0x03;
    public const ROTATE_EVENT = 0x04;
    public const INTVAR_EVENT = 0x05;
    public const RAND_EVENT = 0x0d;
    public const USER_VAR_EVENT = 0x0e;
    public const FORMAT_DESCRIPTION_EVENT = 0x0f;
    public const XID_EVENT = 0x10;
    public const BEGIN_LOAD_QUERY_EVENT = 0x11;
    public const EXECUTE_LOAD_QUERY_EVENT = 0x12;
    public const TABLE_MAP_EVENT = 0x13;
    public const WRITE_ROWS_EVENT_V1 = 0x17;
    public const UPDATE_ROWS_EVENT_V1 = 0x18;
    public const DELETE_ROWS_EVENT_V1 = 0x19;
    public const INCIDENT_EVENT = 0x1a;
    public const HEARTBEAT_LOG_EVENT = 0x1b;
    public const IGNORABLE_LOG_EVENT = 0x1c;
    public const ROWS_QUERY_LOG_EVENT = 0x1d;
    public const WRITE_ROWS_EVENT_V2 = 0x1e;
    public const UPDATE_ROWS_EVENT_V2 = 0x1f;
    public const DELETE_ROWS_EVENT_V2 = 0x20;
    public const GTID_LOG_EVENT = 0x21;
    public const ANONYMOUS_GTID_LOG_EVENT = 0x22;
    public const PREVIOUS_GTIDS_LOG_EVENT = 0x23;
    public const TRANSACTION_CONTEXT_EVENT = 0x24;
    public const VIEW_CHANGE_EVENT = 0x25;
    public const XA_PREPARE_LOG_EVENT = 0x26;
    public const PARTIAL_UPDATE_ROWS_EVENT = 0x27;
    public const TRANSACTION_PAYLOAD_EVENT = 0x28;

    private const NAMES = [
        self::UNKNOWN_EVENT => 'UNKNOWN_EVENT',
        self::START_EVENT_V3 => 'START_EVENT_V3',
        self::QUERY_EVENT => 'QUERY',
        self::STOP_EVENT => 'STOP',
        self::ROTATE_EVENT => 'ROTATE',
        self::INTVAR_EVENT => 'INTVAR',
        self::RAND_EVENT => 'RAND',
        self::USER_VAR_EVENT => 'USER_VAR',
        self::FORMAT_DESCRIPTION_EVENT => 'FORMAT_DESCRIPTION',
        self::XID_EVENT => 'XID',
        self::BEGIN_LOAD_QUERY_EVENT => 'BEGIN_LOAD_QUERY',
        self::EXECUTE_LOAD_QUERY_EVENT => 'EXECUTE_LOAD_QUERY',
        self::TABLE_MAP_EVENT => 'TABLE_MAP',
        self::WRITE_ROWS_EVENT_V1 => 'WRITE_ROWS(v1)',
        self::UPDATE_ROWS_EVENT_V1 => 'UPDATE_ROWS(v1)',
        self::DELETE_ROWS_EVENT_V1 => 'DELETE_ROWS(v1)',
        self::INCIDENT_EVENT => 'INCIDENT',
        self::HEARTBEAT_LOG_EVENT => 'HEARTBEAT',
        self::IGNORABLE_LOG_EVENT => 'IGNORABLE',
        self::ROWS_QUERY_LOG_EVENT => 'ROWS_QUERY',
        self::WRITE_ROWS_EVENT_V2 => 'WRITE_ROWS',
        self::UPDATE_ROWS_EVENT_V2 => 'UPDATE_ROWS',
        self::DELETE_ROWS_EVENT_V2 => 'DELETE_ROWS',
        self::GTID_LOG_EVENT => 'GTID',
        self::ANONYMOUS_GTID_LOG_EVENT => 'ANONYMOUS_GTID',
        self::PREVIOUS_GTIDS_LOG_EVENT => 'PREVIOUS_GTIDS',
        self::TRANSACTION_CONTEXT_EVENT => 'TRANSACTION_CONTEXT',
        self::VIEW_CHANGE_EVENT => 'VIEW_CHANGE',
        self::XA_PREPARE_LOG_EVENT => 'XA_PREPARE',
        self::PARTIAL_UPDATE_ROWS_EVENT => 'PARTIAL_UPDATE_ROWS',
        self::TRANSACTION_PAYLOAD_EVENT => 'TRANSACTION_PAYLOAD',
    ];

    public static function name(int $type): string
    {
        return self::NAMES[$type] ?? sprintf('EVENT_0x%02x', $type);
    }
}
