# mogu/mysql-binlog

MySQL replication-protocol client for PHP: register your process as a **replica** and stream/parse binlog events in real time — built on [amphp/socket](https://github.com/amphp/socket), no extensions required beyond OpenSSL.

`amphp/mysql` covers the query protocol only. This package implements the rest of the wire protocol by hand:

- TCP + handshake v10 auth (`caching_sha2_password` incl. RSA full auth, `mysql_native_password`, auth-switch)
- `SET @master_binlog_checksum` / heartbeat period, then `COM_BINLOG_DUMP` with a unique server-id
- Streaming parse of the event flow: multi-packet (>16 MB) reassembly, CRC32-stripped bodies
- Full row-event decoding for **MySQL 8.4** (explicit column-count field), including `TABLE_MAP`, rows v1/v2, UPDATE before/after images
- All common column types: INT family, DECIMAL (negative values are stored bit-inverted), FLOAT/DOUBLE, VARCHAR (1/2-byte meta-aware length prefix), BIT, ENUM/SET, BLOB/VARBINARY, JSON, DATETIME(0-6)/TIMESTAMP2/TIME2/DATE/YEAR

## Requirements

- PHP >= 8.1 with `ext-openssl`
- A MySQL account with `REPLICATION SLAVE` privilege: `GRANT REPLICATION SLAVE ON *.* TO user@'%';`
- Row-based binlog (`binlog_format=ROW`) for row events

## Installation

```bash
composer require mogu/mysql-binlog
```

## Quick start

```php
use Mogu\Binlog\BinlogConnection;
use Mogu\Binlog\BinlogParser;

Amp\async(function () {
    // 1. Register as a replica. The server-id must be unique across the whole
    //    replication topology — two replicas with the same id will kick each other.
    $replica = BinlogConnection::connect('127.0.0.1', 3306, 'user', 'password', 8101);

    // 2. Session setup (checksum + heartbeat), then request the event stream
    $replica->setupReplication();
    $replica->startDump('binlog.000045', 4); // file + position, get them from
                                             // SHOW BINARY LOG STATUS (8.4+)
                                             // or SHOW MASTER STATUS (older)

    // 3. Parse the pushed events
    $parser = new BinlogParser(); // optionally pass column names keyed by
                                  // "schema.table" for named row output
    while (true) {
        $event = $parser->parse($replica->readEvent());

        if (isset($event['action'])) { // WRITE/UPDATE/DELETE_ROWS
            foreach ($event['rows'] as $row) {
                // $row['before'] / $row['after'] are column => value maps
            }
        }
    }
})->await();
```

Run the live demo (needs `amphp/mysql` for the helper queries):

```bash
composer install
MYSQL_DSN='host=127.0.0.1 user=root password=secret db=test' php examples/subscribe.php
```

Then write something in MySQL and watch:

```
[12:36:15] binlog.000045:15938  UPDATE_ROWS     `test`.`costom`  update ×1
    - {name='alice', company_name='测试公司A'}
    + {name='alice', company_name='改名后B'}
```

## Notes & limitations

- **Timestamps** are stored in binlog as UTC epochs; format them in your server's timezone.
- **ENUM/SET** values are decoded as integer index / bitmask, not label strings (join against `information_schema.columns` if you need names).
- **JSON** values are reported as `<json:N bytes>` placeholders (MySQL's binary JSON format is not decoded yet).
- Row events follow the **MySQL 8.4** layout (explicit column count after `extra_data_len`). On 5.7/8.0 that field does not exist and `BinlogParser::parseRows()` needs a small adjustment.
- Requests at exactly the end of the current binlog file can make 8.4 fall back to the oldest log and error — `examples/subscribe.php` shows the workaround (start from position 4).
- One `BinlogConnection` is a single blocking dump stream; create one connection per subscription.

## License

MIT — see [LICENSE](LICENSE).
