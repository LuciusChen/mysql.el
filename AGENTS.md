# mysql Development Guide

- This is a pure protocol library with zero UI dependencies.
- Target Emacs 28.1+.
- Loading `mysql.el` must not alter Emacs behavior; activation must stay explicit.
- Public symbols use the `mysql-` prefix.
- Private symbols use the `mysql--` prefix.
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
- Run tests with:

```bash
emacs -batch -L . -l ert -l test/mysql-test.el \
  --eval '(ert-run-tests-batch-and-exit)'
```

- Run package-lint with:

```bash
emacs -Q --batch -L ../package-lint -l package-lint \
  -f package-lint-batch-and-exit mysql.el
```
