# Changelog

Notable user-visible changes are recorded here.

## Unreleased

### Added

- `mysql-query-async` sends a text query without waiting. The process filter reads the response as it arrives and the callback runs once, from a timer, with the result or an error condition. The connection stays busy until then and refuses other commands; `mysql-async-pending-p` reports whether a query is still waiting for its response. After a `mysql-query-error`, such as a query stopped by KILL QUERY, the connection stays usable, and any other error closes it.

### Fixed

- Send each packet header and payload fragment in one socket write to avoid delayed-ACK waits caused by separate short writes. Packet bytes, fragmentation and sequence numbering are unchanged.

## 0.2.4 - 2026-07-15

### Changed

- Every packet sequence is validated, and logical messages and command responses are bounded by `mysql-max-message-bytes` and `mysql-max-response-bytes`. Authentication packets fail closed, and prepared binary rows honor column signedness and decode text, JSON, DECIMAL, BIT, and binary values from full column metadata.
