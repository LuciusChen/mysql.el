# mysql Development Guide

- This is a pure protocol library with zero UI dependencies.
- Target Emacs 28.1+.
- Loading `mysql.el` must not alter Emacs behavior; activation must stay explicit.
- Public symbols use the `mysql-` prefix.
- Private symbols use the `mysql--` prefix.
- Downstream packages must use public `mysql-` APIs only. If a client needs
  protocol behavior that currently exists only in `mysql--*`, add a documented
  public wrapper here instead of telling the client to call internals.
- Do not add any `clutch` or UI dependencies.
- Require `cl-lib` explicitly when using `cl-*` APIs; do not rely on transitive loading.
- Avoid `eval-when-compile` for runtime-needed dependencies.
- Byte-compiling `mysql.el` must produce zero warnings.
- All public functions must have docstrings.
- `checkdoc` compliance is required.
- `package-lint` compliance is required for the distributable package entry file set.
- Use `mysql-error` and its subtypes for error signaling; do not swallow errors.
- Error messages should describe the current problem, not issue command-style requirements.
- For MELPA naming compliance, all library symbols must use the `mysql-` prefix.
- Run tests with (`load-prefer-newer` keeps a stale `.elc` from shadowing
  edited sources):

```bash
emacs -Q --batch --eval '(setq load-prefer-newer t)' \
  -L . -l ert -l test/mysql-test.el \
  --eval '(ert-run-tests-batch-and-exit)'
```

- That run skips every live test.  Live tests need a server and
  `mysql-test-password`; CI runs them against MySQL 8.0 with TLS:

```bash
emacs -Q --batch --eval '(setq load-prefer-newer t)' \
  -L . -l ert -l test/mysql-test.el \
  --eval '(setq mysql-test-password "test" mysql-test-port 3306
                mysql-test-tls-enabled t mysql-tls-verify-server nil)' \
  --eval '(ert-run-tests-batch-and-exit)'
```

- CI covers MySQL 8.0 only.  After changing the handshake, capabilities,
  authentication plugins, TLS, packet framing or result decoding, also run the
  live suite against MySQL 5.6, MySQL 8.4 and MariaDB 10.11, setting
  `mysql-test-port` for each, or say which were not run.  Leave
  `mysql-test-tls-enabled` nil for a server without TLS.

- Byte-compile with zero warnings, then delete the generated files so they
  cannot shadow the source in later runs:

```bash
emacs -Q --batch --eval '(setq byte-compile-error-on-warn t)' \
  -L . -f batch-byte-compile mysql.el test/mysql-test.el \
  && rm -f *.elc test/*.elc
```

- Run checkdoc, which must print nothing, and package-lint, installed with
  package.el.  The checkdoc command turns on the imperative-verb check,
  which Emacs 31 and later leave off by default:

```bash
emacs -Q --batch --eval "(require 'checkdoc)" \
  --eval '(setq checkdoc-verb-check-experimental-flag t)' \
  --eval '(checkdoc-file "mysql.el")'

emacs -Q --batch --eval "(require 'package)" --eval "(package-initialize)" \
  -l package-lint -f package-lint-batch-and-exit mysql.el
```

## Wire invariants

- A connection runs one command at a time.  A busy connection, or one whose
  abandoned response still awaits `mysql-drain-query-response`, refuses a new
  command before sending anything.
- Every packet's sequence id is checked, and `mysql-max-message-bytes` and
  `mysql-max-response-bytes` bound a message and a command response; a
  violation closes the connection.
- A query error is signaled only after its ERR packet has been consumed, so the
  connection stays usable.
- A timeout, quit or throw before the first response packet is consumed leaves
  that response for `mysql-drain-query-response`.  Once parsing has started,
  the same exit closes the connection: the stream position is inside the
  response, and nothing may reuse a connection whose position is unknown.
- An asynchronous query completes exactly once.  The process filter hands the
  response only whole packets, the callback runs from a timer and never inside
  the filter, and a send cut short, including by a quit, closes the connection
  without calling back.

## Releases

- Record user-visible changes in `CHANGELOG.md` under `Unreleased` in the same
  change; pure test or internal cleanup needs no entry.
- Only a release changes `;; Version:` in `mysql.el`, moves the `Unreleased`
  entries under the new version, and is tagged `vX.Y.Z`.  Keep
  version-specific prose out of `README.org`.
- MELPA builds `mysql` from `main`, so every merge reaches MELPA users.  No
  version has been tagged yet.
