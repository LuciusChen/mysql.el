# Changelog

Notable user-visible changes are recorded here.

## Unreleased

### Added

- `mysql-refresh-current-database` asks the server which database a connection uses and records it, so `mysql-current-database` follows a `USE` that was run through `mysql-query`.
- `mysql-query-async` sends a text query without waiting. The process filter reads the response as it arrives and the callback runs once, from a timer, with the result or an error condition. The connection stays busy until then and refuses other commands; `mysql-async-pending-p` reports whether a query is still waiting for its response. After a `mysql-query-error`, such as a query stopped by KILL QUERY, the connection stays usable, and any other error closes it.

### Fixed

- An ERR packet that answers authentication signals `mysql-auth-error` only when it refuses the credentials themselves, SQLSTATE class 28 such as error 1045, or carries no SQLSTATE. Any other refusal, such as an unknown database (1049), a database the user may not use (1044), a locked account or too many connections (1040), now signals `mysql-connection-error` with the server's message, where it was reported as failed authentication. An ERR sent in place of the handshake is a `mysql-connection-error` too; it was read as a handshake of protocol version 255, or, when the server closed the connection before Emacs saw it open, lost behind "Failed to connect".

## 0.2.4 - 2026-07-15

### Changed

- Every packet sequence is validated, and logical messages and command responses are bounded by `mysql-max-message-bytes` and `mysql-max-response-bytes`. Authentication packets fail closed, and prepared binary rows honor column signedness and decode text, JSON, DECIMAL, BIT, and binary values from full column metadata.
