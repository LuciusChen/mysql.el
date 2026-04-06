# mysql-wire Development Guide

- This is a pure protocol library with zero UI dependencies.
- Target Emacs 28.1+.
- Public symbols use the `mysql-wire-` prefix.
- Private symbols use the `mysql-wire--` prefix.
- Do not add any `clutch` or UI dependencies.
- Byte-compiling `mysql-wire.el` must produce zero warnings.
- All public functions must have docstrings.
- `checkdoc` compliance is required.
- Use `mysql-wire-error` and its subtypes for error signaling; do not swallow errors.
- For MELPA naming compliance, all library symbols must use the `mysql-wire-` prefix.
- Run tests with:

```bash
emacs -batch -L . -l ert -l test/mysql-wire-test.el \
  --eval '(ert-run-tests-batch-and-exit)'
```
