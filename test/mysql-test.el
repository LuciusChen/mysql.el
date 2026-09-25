;;; mysql-test.el --- ERT tests for the MySQL wire protocol client -*- lexical-binding: t; -*-

;; Author: Lucius Chen <chenyh572@gmail.com>
;; Maintainer: Lucius Chen <chenyh572@gmail.com>
;; URL: https://github.com/LuciusChen/mysql.el

;;; Commentary:

;; ERT tests for the MySQL client.
;;
;; Tests marked with :mysql-live require a running MySQL instance:
;;   docker run -e MYSQL_ROOT_PASSWORD=test -p 3306:3306 mysql:8
;;
;; Run all unit tests from the repository root; `load-prefer-newer'
;; keeps a stale .elc from shadowing edited sources:
;;   emacs -Q --batch --eval '(setq load-prefer-newer t)' \
;;     -L . -l ert -l test/mysql-test.el \
;;     --eval '(ert-run-tests-batch-and-exit)'
;;
;; Run live integration tests; the TLS-tagged tests stay skipped unless
;; `mysql-test-tls-enabled' is also set (the docker image above serves
;; TLS out of the box):
;;   emacs -Q --batch --eval '(setq load-prefer-newer t)' \
;;     -L . -l ert -l test/mysql-test.el \
;;     --eval '(setq mysql-test-password "test"
;;                   mysql-test-tls-enabled t)' \
;;     --eval '(ert-run-tests-batch-and-exit)'

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'hex-util)
(require 'mysql)

;;;; Test configuration for live tests

(defvar mysql-test-host "127.0.0.1")
(defvar mysql-test-port 3306)
(defvar mysql-test-user "root")
(defvar mysql-test-password nil
  "Set this to enable live integration tests.")
(defvar mysql-test-database "mysql")
(defvar mysql-test-tls-enabled nil
  "Set this to enable TLS live tests.")

(defconst mysql-test--unsupported-caps
  '((compress . #x00000020)
    (local-files . #x00000080)
    (multi-statements . #x00010000)
    (multi-results . #x00020000)
    (ps-multi-results . #x00040000)
    (connect-attrs . #x00100000)
    (plugin-auth-lenenc-data . #x00200000)
    (session-track . #x00800000)
    (deprecate-eof . #x01000000)
    (optional-resultset-metadata . #x02000000)
    (zstd-compression . #x04000000)
    (query-attributes . #x08000000)
    (multi-factor-authentication . #x10000000))
  "MySQL capability flags that the protocol client does not implement.")

(defun mysql-test--packet-client-flags (packet)
  "Return the 4-byte client capability flags from PACKET."
  (logior (aref packet 0)
          (ash (aref packet 1) 8)
          (ash (aref packet 2) 16)
          (ash (aref packet 3) 24)))

(defun mysql-test--assert-no-unsupported-caps (flags)
  "Assert FLAGS do not advertise unsupported MySQL protocol features."
  (dolist (cap mysql-test--unsupported-caps)
    (ert-info ((format "capability: %s" (car cap)))
      (should (zerop (logand flags (cdr cap)))))))

;;;; Unit tests — protocol helpers (no server needed)

(ert-deftest mysql-test-int-le-bytes ()
  "Test little-endian integer encoding."
  (should (equal (mysql--int-le-bytes 0 1) (unibyte-string 0)))
  (should (equal (mysql--int-le-bytes 255 1) (unibyte-string 255)))
  (should (equal (mysql--int-le-bytes #x0102 2) (unibyte-string #x02 #x01)))
  (should (equal (mysql--int-le-bytes #x010203 3) (unibyte-string #x03 #x02 #x01)))
  (should (equal (mysql--int-le-bytes #x01020304 4)
                 (unibyte-string #x04 #x03 #x02 #x01))))

(ert-deftest mysql-test-lenenc-int-bytes ()
  "Test length-encoded integer encoding."
  (should (equal (mysql--lenenc-int-bytes 0) (unibyte-string 0)))
  (should (equal (mysql--lenenc-int-bytes 250) (unibyte-string 250)))
  (should (equal (mysql--lenenc-int-bytes 251)
                 (concat (unibyte-string #xfc) (mysql--int-le-bytes 251 2))))
  (should (equal (mysql--lenenc-int-bytes #xffff)
                 (concat (unibyte-string #xfc) (mysql--int-le-bytes #xffff 2))))
  (should (equal (mysql--lenenc-int-bytes #x10000)
                 (concat (unibyte-string #xfd) (mysql--int-le-bytes #x10000 3)))))

(ert-deftest mysql-test-lenenc-int-from-string ()
  "Test reading length-encoded integers from a string."
  (should (equal (mysql--read-lenenc-int-from-string (unibyte-string 42) 0)
                 '(42 . 1)))
  (should (equal (mysql--read-lenenc-int-from-string
                  (unibyte-string #xfc #x01 #x00) 0)
                 '(1 . 3)))
  (should (equal (mysql--read-lenenc-int-from-string
                  (unibyte-string #xfd #x01 #x00 #x00) 0)
                 '(1 . 4))))

(ert-deftest mysql-test-lenenc-int-from-string-rejects-truncated ()
  "Truncated length-encoded integers should signal `mysql-protocol-error'."
  (dolist (packet (list ""
                        (unibyte-string #xfc #x01)
                        (unibyte-string #xfd #x01 #x02)
                        (unibyte-string #xfe #x00 #x00 #x02 #x00)))
    (should-error (mysql--read-lenenc-int-from-string packet 0)
                  :type 'mysql-protocol-error)))

(ert-deftest mysql-test-read-lenenc-string-from-string ()
  "Test reading length-encoded strings."
  (should (equal (mysql--read-lenenc-string-from-string
                  (concat (unibyte-string 5) "hello") 0)
                 '("hello" . 6)))
  (should (equal (mysql--read-lenenc-string-from-string
                  (concat (unibyte-string 0)) 0)
                 '("" . 1))))

(ert-deftest mysql-test-auth-native-password ()
  "Test mysql_native_password against a known-answer vector.
Vector independently verified with Python's hashlib for password
\"secret\" and salt \"12345678901234567890\"."
  ;; Empty password should return empty string
  (should (equal (mysql--auth-native-password "" "12345678901234567890") ""))
  (should (equal (mysql--auth-native-password nil "12345678901234567890") ""))
  (should (equal (encode-hex-string
                  (mysql--auth-native-password "secret" "12345678901234567890"))
                 "0f8b9033e0897c0a8338ebe3dea9010dda47ab56")))

(ert-deftest mysql-test-auth-caching-sha2-password ()
  "Test caching_sha2_password against a known-answer vector.
Vector independently verified with Python's hashlib for password
\"secret\" and salt \"12345678901234567890\"."
  (should (equal (mysql--auth-caching-sha2-password "" "12345678901234567890") ""))
  (should (equal (encode-hex-string
                  (mysql--auth-caching-sha2-password "secret" "12345678901234567890"))
                 "51ecd6dedbd34d5445c0a190d4f51acf0d23b94db66c91f3f789faa9193751cd")))

(ert-deftest mysql-test-parse-ok-packet ()
  "Test OK packet parsing."
  (let* ((packet (concat (unibyte-string #x00  ; OK marker
                                         #x01  ; affected_rows = 1
                                         #x00  ; last_insert_id = 0
                                         #x02 #x00  ; status_flags
                                         #x00 #x00)))  ; warnings
         (info (mysql--parse-ok-packet packet)))
    (should (= (plist-get info :affected-rows) 1))
    (should (= (plist-get info :last-insert-id) 0))
    (should (= (plist-get info :warnings) 0))))

(ert-deftest mysql-test-parse-err-packet ()
  "Test ERR packet parsing."
  (let* ((packet (concat (unibyte-string #xff          ; ERR marker
                                         #x15 #x04)   ; error code 1045
                         "#"                           ; SQL state marker
                         "28000"                       ; SQL state
                         "Access denied"))
         (info (mysql--parse-err-packet packet)))
    (should (= (plist-get info :code) 1045))
    (should (equal (plist-get info :state) "28000"))
    (should (equal (plist-get info :message) "Access denied"))))

(ert-deftest mysql-test-packet-type ()
  "Test packet type detection."
  (should (eq (mysql--packet-type (unibyte-string #x00)) 'ok))
  (should (eq (mysql--packet-type (unibyte-string #xff)) 'err))
  (should (eq (mysql--packet-type (unibyte-string #xfe)) 'eof))
  (should (eq (mysql--packet-type (unibyte-string #xfb)) 'local-infile))
  (should (eq (mysql--packet-type (unibyte-string #x03 #x01 #x02)) 'data)))

(ert-deftest mysql-test-parse-value-dispatches-by-type ()
  "`mysql--parse-value' dispatches every scalar and date/time type correctly."
  (dolist (case (list (list "42" mysql-type-long 42)
                      (list "3.14" mysql-type-float 3.14)
                      (list "2024" mysql-type-year 2024)
                      (list "hello" mysql-type-var-string "hello")
                      (list nil mysql-type-long nil)
                      (list "2024-03-15" mysql-type-date
                            '(:year 2024 :month 3 :day 15))
                      (list "0000-00-00" mysql-type-date nil)
                      (list "" mysql-type-date nil)
                      (list "13:45:30" mysql-type-time
                            '(:hours 13 :minutes 45 :seconds 30 :negative nil))
                      (list "-02:30:00" mysql-type-time
                            '(:hours 2 :minutes 30 :seconds 0 :negative t))
                      (list "" mysql-type-time nil)
                      (list "2024-03-15 13:45:30" mysql-type-datetime
                            '(:year 2024 :month 3 :day 15
                              :hours 13 :minutes 45 :seconds 30))
                      (list "2024-01-01 00:00:00.123456" mysql-type-datetime
                            '(:year 2024 :month 1 :day 1
                              :hours 0 :minutes 0 :seconds 0))
                      (list "0000-00-00 00:00:00" mysql-type-datetime nil)
                      (list "" mysql-type-datetime nil)
                      (list "2024-03-15 13:45:30" mysql-type-timestamp
                            '(:year 2024 :month 3 :day 15
                              :hours 13 :minutes 45 :seconds 30))))
    (pcase-let ((`(,value ,type ,expected) case))
      (ert-info ((format "value: %S type: %S" value type))
        (should (equal (mysql--parse-value value type) expected))))))

(ert-deftest mysql-test-parse-value-decimal-stays-exact ()
  "DECIMAL survives as its exact digit string in both protocols.
The type exists to keep values a float cannot represent."
  (let ((digits "1234567890123456789.123456789"))
    (should (equal (mysql--parse-value digits mysql-type-newdecimal) digits))
    (should (equal (mysql--parse-value digits mysql-type-decimal) digits))
    (should (equal (mysql--parse-typed-value digits mysql-type-newdecimal)
                   digits))))

(ert-deftest mysql-test-parse-value-binary-columns-keep-bytes ()
  "Text protocol string decoding must follow the column's character set.
A BLOB decoded as UTF-8 corrupts bytes that are not valid sequences and
cannot round-trip."
  (let ((bytes (unibyte-string #xff #x00 #xfe #x80)))
    ;; Binary character set: bytes come back untouched.
    (should (equal (mysql--parse-value
                    bytes (list :type mysql-type-blob
                                :character-set mysql--binary-character-set
                                :flags mysql--column-flag-binary))
                   bytes))
    ;; GEOMETRY is bytes regardless of metadata beyond its type.
    (should (equal (mysql--parse-value
                    bytes (list :type mysql-type-geometry))
                   bytes))
    ;; A text column still decodes.
    (should (equal (mysql--parse-value
                    (encode-coding-string "héllo" 'utf-8)
                    (list :type mysql-type-var-string :character-set 224))
                   "héllo"))
    ;; Without metadata, bare type codes keep decoding as text.
    (should (equal (mysql--parse-value
                    (encode-coding-string "plain" 'utf-8)
                    mysql-type-blob)
                   "plain"))))

;;;; Extended type system tests

(ert-deftest mysql-test-parse-bit ()
  "Test BIT binary string parsing."
  (should (= (mysql--parse-bit (unibyte-string #x01)) 1))
  (should (= (mysql--parse-bit (unibyte-string #x00 #xff)) 255))
  (should (= (mysql--parse-bit (unibyte-string #x01 #x00)) 256)))

(ert-deftest mysql-test-custom-type-parser ()
  "Test custom type parser override."
  (let ((mysql-type-parsers (list (cons mysql-type-long
                                       (lambda (v) (concat "custom:" v))))))
    (should (equal (mysql--parse-value "42" mysql-type-long) "custom:42")))
  ;; Without override, original behavior
  (should (= (mysql--parse-value "42" mysql-type-long) 42)))

;;;; Convenience API unit tests

(ert-deftest mysql-test-escape-identifier ()
  "Test identifier escaping."
  (should (equal (mysql-escape-identifier "table") "`table`"))
  (should (equal (mysql-escape-identifier "my`table") "`my``table`"))
  (should (equal (mysql-escape-identifier "normal_name") "`normal_name`")))

(ert-deftest mysql-test-escape-literal ()
  "Test literal escaping."
  (should (equal (mysql-escape-literal "hello") "'hello'"))
  (should (equal (mysql-escape-literal "it's") "'it\\'s'"))
  (should (equal (mysql-escape-literal "line\nbreak") "'line\\nbreak'"))
  (should (equal (mysql-escape-literal "back\\slash") "'back\\\\slash'"))
  ;; Ctrl-Z terminates a statement for the Windows client and must not reach
  ;; the server raw.
  (should (equal (mysql-escape-literal (concat "a" (string ?\C-z) "b"))
                 "'a\\Zb'"))
  ;; The escape set must not capture the letters spelling its own hex escape.
  (should (equal (mysql-escape-literal "x1a") "'x1a'")))

(ert-deftest mysql-test-uri-parsing ()
  "MySQL URIs parse through the public entry with percent decoding."
  (cl-letf (((symbol-function 'mysql-connect) #'list))
    (should (equal (mysql-connect-uri
                    "mysql://user:p%40ss@localhost:3307/app%2Fdata")
                   '(:host "localhost" :port 3307 :user "user"
                     :password "p@ss" :database "app/data")))
    ;; No port and no database fall back to defaults.
    (should (equal (mysql-connect-uri "mysql://root:pw@db.internal")
                   '(:host "db.internal" :port 3306 :user "root"
                     :password "pw" :database nil)))))

(ert-deftest mysql-test-transaction-state-helpers ()
  "Test autocommit and transaction status helpers."
  (let ((conn (make-mysql-conn :status-flags
                               (logior mysql--server-status-autocommit
                                       mysql--server-status-in-transaction))))
    (should (mysql-autocommit-p conn))
    (should (mysql-in-transaction-p conn)))
  (let ((conn (make-mysql-conn :status-flags mysql--server-status-in-transaction)))
    (should-not (mysql-autocommit-p conn))
    (should (mysql-in-transaction-p conn)))
  (let ((conn (make-mysql-conn)))
    (should (mysql-autocommit-p conn))
    (should-not (mysql-in-transaction-p conn))))

(ert-deftest mysql-test-transaction-helpers-issue-sql ()
  "Test that the autocommit/commit/rollback helpers send the expected SQL."
  (let ((conn (make-mysql-conn))
        (queries nil))
    (cl-letf (((symbol-function 'mysql-query)
               (lambda (_conn sql)
                 (push sql queries)
                 (make-mysql-result :status "OK"))))
      (mysql-set-autocommit conn nil)
      (mysql-set-autocommit conn t)
      (mysql-commit conn)
      (mysql-rollback conn))
    (should (equal (nreverse queries)
                   '("SET autocommit = 0" "SET autocommit = 1"
                     "COMMIT" "ROLLBACK")))))

(ert-deftest mysql-test-client-capability-flags ()
  "Client flags should match implemented protocol paths."
  (let* ((conn (make-mysql-conn :host "localhost"
                                :port 3306
                                :user "root"
                                :database "test"
                                :tls t))
         (flags (mysql--client-capabilities conn)))
    (should (not (zerop (logand flags mysql--cap-long-password))))
    (should (not (zerop (logand flags mysql--cap-protocol-41))))
    (should (not (zerop (logand flags mysql--cap-transactions))))
    (should (not (zerop (logand flags mysql--cap-secure-connection))))
    (should (not (zerop (logand flags mysql--cap-plugin-auth))))
    (should (not (zerop (logand flags mysql--cap-ssl))))
    (should (not (zerop (logand flags mysql--cap-connect-with-db))))
    (mysql-test--assert-no-unsupported-caps flags)))

;;;; TLS unit tests

(ert-deftest mysql-test-ssl-request-packet ()
  "Test SSL_REQUEST packet structure."
  (let* ((conn (make-mysql-conn :host "localhost" :port 3306
                                :user "root" :database "test"))
         (packet (mysql--build-ssl-request conn)))
    ;; SSL_REQUEST is exactly 32 bytes
    (should (= (length packet) 32))
    ;; Check client flags include SSL capability
    (let ((flags (mysql-test--packet-client-flags packet)))
      (should (not (zerop (logand flags mysql--cap-ssl))))
      (should (not (zerop (logand flags mysql--cap-protocol-41))))
      (mysql-test--assert-no-unsupported-caps flags))
    ;; Character set byte should be 45 (utf8mb4)
    (should (= (aref packet 8) 45))
    ;; Bytes 9-31 should be zero (filler)
    (let ((all-zero t))
      (dotimes (i 23)
        (unless (= (aref packet (+ 9 i)) 0) (setq all-zero nil)))
      (should all-zero))))

;;;; Prepared statement unit tests

(ert-deftest mysql-test-build-execute-packet ()
  "Test COM_STMT_EXECUTE packet construction."
  (let* ((stmt (make-mysql-stmt :id 1 :param-count 2 :column-count 1
                                :conn nil
                                :param-definitions nil
                                :column-definitions nil))
         (packet (mysql--build-execute-packet stmt '(42 "hello"))))
    ;; First byte: command 0x17
    (should (= (aref packet 0) #x17))
    ;; stmt_id: 4 bytes LE = 1
    (should (= (aref packet 1) 1))
    (should (= (aref packet 2) 0))
    ;; flags: 0x00
    (should (= (aref packet 5) #x00))
    ;; iteration_count: 1
    (should (= (aref packet 6) 1))
    ;; new_params_bound_flag: first execute sends parameter types
    (should (= (aref packet 11) #x01))))

(ert-deftest mysql-test-build-execute-packet-reuses-bound-types ()
  "COM_STMT_EXECUTE should omit type metadata when types are unchanged."
  (let* ((types (mysql--param-type-vector '(1 "a")))
         (stmt (make-mysql-stmt :id 1 :param-count 2 :column-count 1
                                :parameter-types types))
         (packet (mysql--build-execute-packet stmt '(42 "hi") types)))
    (should (= (aref packet 11) #x00))
    (should (= (length packet) 23))
    (should (= (aref packet 20) 2))
    (should (equal (substring packet 21 23) "hi"))))

(ert-deftest mysql-test-build-fetch-packet ()
  "Test COM_STMT_FETCH packet construction."
  (let* ((stmt (make-mysql-stmt :id #x01020304 :param-count 0))
         (packet (mysql--build-fetch-packet stmt 25)))
    (should (= (aref packet 0) #x1c))
    (should (equal (substring packet 1 5)
                   (unibyte-string #x04 #x03 #x02 #x01)))
    (should (equal (substring packet 5 9)
                   (mysql--int-le-bytes 25 4)))))

(ert-deftest mysql-test-null-bitmap ()
  "Test NULL bitmap construction in execute packet."
  (let* ((stmt (make-mysql-stmt :id 1 :param-count 3 :column-count 0
                                :conn nil
                                :param-definitions nil
                                :column-definitions nil))
         (packet (mysql--build-execute-packet stmt '(nil 42 nil))))
    ;; NULL bitmap starts at offset 10 (1+4+1+4)
    ;; Params: nil=bit0, 42=bit1, nil=bit2 → bitmap = 0b101 = 5
    (should (= (aref packet 10) 5))))

(ert-deftest mysql-test-response-reads-bind-input-and-busy ()
  "Response reads run with `throw-on-input' nil and CONN marked busy.
Completion frameworks abort via `while-no-input'; a read interrupted
mid-response would desynchronize the stream, and the busy flag is what
rejects overlapping commands."
  (dolist (command '(prepare execute))
    (ert-info ((format "command: %s" command))
      (let* ((conn (make-mysql-conn))
             (stmt (make-mysql-stmt :conn conn :id 1 :param-count 0))
             (response (pcase command
                         ('prepare (unibyte-string #x00 #x01 #x00 #x00 #x00
                                                   #x00 #x00 #x00 #x00
                                                   #x00 #x00 #x00))
                         ('execute (unibyte-string #x00 #x01 #x00 #x02
                                                   #x00 #x00 #x00))))
             observed-throw-on-input
             observed-busy)
        (cl-letf (((symbol-function 'mysql--send-packet) #'ignore)
                  ((symbol-function 'mysql--read-packet)
                   (lambda (conn)
                     (setq observed-throw-on-input throw-on-input
                           observed-busy (mysql-conn-busy conn))
                     response)))
          (let ((throw-on-input 'mysql-test-tag))
            (pcase command
              ('prepare (mysql-prepare conn "SELECT 1"))
              ('execute (mysql-execute stmt)))))
        (should-not observed-throw-on-input)
        (should observed-busy)
        (should-not (mysql-conn-busy conn))))))

(ert-deftest mysql-test-execute-caches-parameter-types ()
  "COM_STMT_EXECUTE should rebind parameter types only when they change."
  (let* ((conn (make-mysql-conn))
         (stmt (make-mysql-stmt :conn conn :id 1 :param-count 2))
         packets)
    (cl-letf (((symbol-function 'mysql--send-packet)
               (lambda (_conn packet)
                 (push packet packets)))
              ((symbol-function 'mysql--read-packet)
               (lambda (_conn)
                 (unibyte-string #x00 #x01 #x00 #x02 #x00 #x00 #x00))))
      (mysql-execute stmt 1 "a")
      (mysql-execute stmt 2 "bb"))
    (setq packets (nreverse packets))
    (should (= (aref (nth 0 packets) 11) #x01))
    (should (= (aref (nth 1 packets) 11) #x00))
    (should (equal (mysql-stmt-parameter-types stmt)
                   (mysql--param-type-vector '(2 "bb"))))))

(ert-deftest mysql-test-execute-cursor-returns-cursor ()
  "COM_STMT_EXECUTE with cursor flag should return a cursor object."
  (let* ((conn (make-mysql-conn))
         (stmt (make-mysql-stmt :conn conn :id 7 :param-count 1))
         (columns (list (list :name "id" :type mysql-type-longlong)))
         packets)
    (cl-letf (((symbol-function 'mysql--send-packet)
               (lambda (_conn packet)
                 (push packet packets)))
              ((symbol-function 'mysql--read-packet)
               (lambda (_conn)
                 (unibyte-string 1)))
              ((symbol-function 'mysql--read-column-definitions)
               (lambda (_conn col-count)
                 (should (= col-count 1))
                 columns)))
      (let ((cursor (mysql-execute-cursor stmt 42)))
        (should (mysql-cursor-p cursor))
        (should (eq (mysql-cursor-stmt cursor) stmt))
        (should (eq (mysql-cursor-columns cursor) columns))))
    (let ((packet (car packets)))
      (should (= (aref packet 0) #x17))
      (should (= (aref packet 5) mysql--stmt-cursor-read-only)))))

(ert-deftest mysql-test-fetch-updates-cursor-exhaustion ()
  "COM_STMT_FETCH should update cursor state from EOF status flags."
  (let* ((conn (make-mysql-conn))
         (stmt (make-mysql-stmt :conn conn :id 9 :param-count 0))
         (columns (list (list :name "id" :type mysql-type-longlong)))
         (cursor (make-mysql-cursor :stmt stmt :columns columns))
         packets)
    (cl-letf (((symbol-function 'mysql--send-packet)
               (lambda (_conn packet)
                 (push packet packets)))
              ((symbol-function 'mysql--read-binary-rows-with-status)
               (lambda (_conn read-columns)
                 (should (eq read-columns columns))
                 (list :rows '((1) (2))
                       :warnings 0
                       :status-flags mysql--server-status-last-row-sent))))
      (let ((result (mysql-fetch cursor 2)))
        (should (equal (mysql-result-rows result) '((1) (2))))
        (should (mysql-cursor-exhausted-p cursor))
        (should (= (mysql-result-warnings result) 0))))
    (let ((packet (car packets)))
      (should (= (aref packet 0) #x1c))
      (should (equal (substring packet 1 5)
                     (mysql--int-le-bytes 9 4)))
      (should (equal (substring packet 5 9)
                     (mysql--int-le-bytes 2 4))))))

(ert-deftest mysql-test-cursor-close-resets-open-cursor ()
  "Closing an open cursor should send COM_STMT_RESET."
  (let* ((conn (make-mysql-conn))
         (stmt (make-mysql-stmt :conn conn :id 11 :parameter-types [cached]))
         (cursor (make-mysql-cursor :stmt stmt))
         packets)
    (cl-letf (((symbol-function 'mysql--send-packet)
               (lambda (_conn packet)
                 (push packet packets)))
              ((symbol-function 'mysql--read-packet)
               (lambda (_conn)
                 (unibyte-string #x00 #x00 #x00 #x02 #x00 #x00 #x00))))
      (should (mysql-cursor-close cursor)))
    (should (mysql-cursor-exhausted-p cursor))
    (should-not (mysql-stmt-parameter-types stmt))
    (let ((packet (car packets)))
      (should (= (aref packet 0) #x1a))
      (should (equal (substring packet 1 5)
                     (mysql--int-le-bytes 11 4))))))

(ert-deftest mysql-test-elisp-to-wire-type ()
  "Test Elisp to MySQL type mapping."
  (should (= (car (mysql--elisp-to-wire-type nil)) mysql-type-null))
  (should (= (car (mysql--elisp-to-wire-type 42)) mysql-type-longlong))
  (should (= (car (mysql--elisp-to-wire-type 3.14)) mysql-type-var-string))
  (should (= (car (mysql--elisp-to-wire-type "hello")) mysql-type-var-string)))

(ert-deftest mysql-test-ieee754-double ()
  "Test IEEE 754 double decoding."
  ;; 3.14 = 0x40091EB851EB851F in big-endian
  ;; Little-endian: 1F 85 EB 51 B8 1E 09 40
  (let ((data (unibyte-string #x1f #x85 #xeb #x51 #xb8 #x1e #x09 #x40)))
    (should (< (abs (- (mysql--ieee754-double-to-float data 0) 3.14)) 0.0001)))
  ;; 0.0
  (let ((data (make-string 8 0)))
    (should (= (mysql--ieee754-double-to-float data 0) 0.0)))
  ;; 1.0 = 0x3FF0000000000000 → LE: 00 00 00 00 00 00 F0 3F
  (let ((data (unibyte-string #x00 #x00 #x00 #x00 #x00 #x00 #xf0 #x3f)))
    (should (= (mysql--ieee754-double-to-float data 0) 1.0))))

(ert-deftest mysql-test-ieee754-single ()
  "Test IEEE 754 single-precision float decoding."
  ;; 1.0 = 0x3F800000 → LE: 00 00 80 3F
  (let ((data (unibyte-string #x00 #x00 #x80 #x3f)))
    (should (= (mysql--ieee754-single-to-float data 0) 1.0)))
  ;; 0.0
  (let ((data (make-string 4 0)))
    (should (= (mysql--ieee754-single-to-float data 0) 0.0))))

(ert-deftest mysql-test-binary-null-p ()
  "Test NULL bitmap bit checking for binary rows."
  ;; Bitmap with bit 2 set (col 0, offset=2): byte 0 = 0b00000100 = 4
  (should (mysql--binary-null-p (unibyte-string #x04) 0))
  (should-not (mysql--binary-null-p (unibyte-string #x04) 1))
  ;; Bit 3 = col 1: byte 0 = 0b00001000 = 8
  (should (mysql--binary-null-p (unibyte-string #x08) 1)))

(ert-deftest mysql-test-decode-binary-datetime ()
  "Test binary DATETIME decoding."
  ;; Length 0: nil
  (let ((data (unibyte-string 0)))
    (should (null (car (mysql--decode-binary-datetime data 0 mysql-type-datetime)))))
  ;; Length 4: date only
  (let ((data (unibyte-string 4 #xe8 #x07 3 15)))  ; 2024-03-15
    (let ((result (car (mysql--decode-binary-datetime data 0 mysql-type-datetime))))
      (should (= (plist-get result :year) 2024))
      (should (= (plist-get result :month) 3))
      (should (= (plist-get result :day) 15))))
  ;; Length 7: date + time
  (let ((data (unibyte-string 7 #xe8 #x07 3 15 13 45 30)))
    (let ((result (car (mysql--decode-binary-datetime data 0 mysql-type-datetime))))
      (should (= (plist-get result :year) 2024))
      (should (= (plist-get result :hours) 13))
      (should (= (plist-get result :seconds) 30)))))

(ert-deftest mysql-test-decode-binary-time ()
  "Test binary TIME decoding."
  ;; Length 0: zero time
  (let ((data (unibyte-string 0)))
    (let ((result (car (mysql--decode-binary-time data 0))))
      (should (= (plist-get result :hours) 0))
      (should (= (plist-get result :minutes) 0))))
  ;; Length 8: non-negative time, 0 days, 13:45:30
  (let ((data (unibyte-string 8 0 0 0 0 0 13 45 30)))
    (let ((result (car (mysql--decode-binary-time data 0))))
      (should (= (plist-get result :hours) 13))
      (should (= (plist-get result :minutes) 45))
      (should (= (plist-get result :seconds) 30))
      (should-not (plist-get result :negative))))
  ;; Length 8: negative time
  (let ((data (unibyte-string 8 1 0 0 0 0 2 30 0)))
    (let ((result (car (mysql--decode-binary-time data 0))))
      (should (plist-get result :negative)))))

(ert-deftest mysql-test-parse-binary-row ()
  "Test binary row parsing."
  ;; 2 columns, no NULLs: INT=42, STRING="hi"
  ;; Packet: 0x00 (header) + null_bitmap(1 byte) + values
  ;; null bitmap for 2 cols: (2+2+7)/8 = 1 byte, all zeros
  ;; INT (LONGLONG): 42 as 8-byte LE
  ;; STRING: lenenc "hi" = 0x02 "hi"
  (let* ((columns (list (list :type mysql-type-longlong :name "id")
                        (list :type mysql-type-var-string :name "name")))
         (packet (concat (unibyte-string #x00)          ; header
                         (unibyte-string #x00)          ; null bitmap
                         (mysql--int-le-bytes 42 8)     ; INT value
                         (unibyte-string 2) "hi"))      ; STRING value
         (row (mysql--parse-binary-row packet columns)))
    (should (= (nth 0 row) 42))
    (should (equal (nth 1 row) "hi"))))

(ert-deftest mysql-test-parse-result-row ()
  "Test result row parsing."
  ;; Row with two string columns: "hello" and "world"
  (let* ((packet (concat (unibyte-string 5) "hello"
                         (unibyte-string 5) "world"))
         (row (mysql--parse-result-row packet 2)))
    (should (equal row '("hello" "world"))))
  ;; Row with NULL value
  (let* ((packet (concat (unibyte-string #xfb)
                         (unibyte-string 3) "foo"))
         (row (mysql--parse-result-row packet 2)))
    (should (equal row '(nil "foo")))))

(ert-deftest mysql-test-parse-result-row-with-type-vector ()
  "Test text row parsing with direct type conversion."
  (let* ((packet (concat (unibyte-string 2) "42"
                         (unibyte-string 5) "hello"))
         (types (vector mysql-type-long mysql-type-var-string))
         (row (mysql--parse-result-row packet 2 types)))
    (should (equal row '(42 "hello")))))

(ert-deftest mysql-test-read-text-rows-keeps-empty-string-row ()
  "A row whose first column is an empty string is not an OK terminator."
  (let ((conn (make-mysql-conn))
        (packets (list (unibyte-string #x00)
                       (unibyte-string #xfe #x00 #x00 #x02 #x00)))
        (read-count 0))
    (cl-letf (((symbol-function 'mysql--read-packet)
               (lambda (_conn)
                 (cl-incf read-count)
                 (pop packets))))
      (should (equal (mysql--read-text-rows
                      conn 1 (list (list :type mysql-type-var-string)))
                     '((""))))
      (should (= read-count 2))
      (should-not packets))))

(ert-deftest mysql-test-result-column-count ()
  "Test result-set header column count decoding.
Truncation is `mysql--read-lenenc-int-from-string' territory; that error
path is covered by `mysql-test-lenenc-int-from-string-rejects-truncated'."
  (should (= (mysql--result-column-count (unibyte-string 3)) 3))
  (should (= (mysql--result-column-count
              (concat (unibyte-string #xfc) (mysql--int-le-bytes 260 2)))
             260)))

(ert-deftest mysql-test-result-eof-updates-transaction-state ()
  "Text and prepared results publish the final server transaction state."
  (dolist (binary '(nil t))
    (dolist (with-row '(nil t))
      (let* ((conn (make-mysql-conn :status-flags 2 :capability-flags 0))
             (stmt (make-mysql-stmt :conn conn :id 1 :param-count 0))
             (columns (list (list :name "id" :type mysql-type-long))))
        (dolist (status '(1 0 2 3 2))
          (let ((packets
                 (append (list (unibyte-string 1))
                         (when with-row
                           (list (if binary (unibyte-string 0 0 42 0 0 0)
                                   (unibyte-string 2 ?4 ?2))))
                         (list (unibyte-string #xfe 0 0 status 0)))))
            (cl-letf (((symbol-function 'mysql--send-packet) #'ignore)
                      ((symbol-function 'mysql--read-packet)
                       (lambda (_conn) (pop packets)))
                      ((symbol-function 'mysql--read-column-definitions)
                       (lambda (_conn _count) columns)))
              (let ((result (if binary (mysql-execute stmt)
                              (mysql-query conn "SELECT id FROM items"))))
                (should (equal (mysql-result-rows result)
                               (when with-row '((42)))))
                (should (= (mysql-conn-status-flags conn) status))
                (should (eq (mysql-in-transaction-p conn)
                            (not (zerop (logand status 1)))))
                (should (eq (mysql-autocommit-p conn)
                            (not (zerop (logand status 2)))))
                (should-not packets)))))))))

(ert-deftest mysql-test-fetch-eof-publishes-status ()
  "Cursor fetch retains status and warnings from its real EOF decoder."
  (let* ((conn (make-mysql-conn :status-flags 2))
         (stmt (make-mysql-stmt :conn conn :id 1 :param-count 0))
         (cursor (make-mysql-cursor :stmt stmt :columns nil)))
    (dolist (status '(65 129))
      (cl-letf (((symbol-function 'mysql--send-packet) #'ignore)
                ((symbol-function 'mysql--read-packet)
                 (lambda (_conn) (unibyte-string #xfe 7 0 status 0))))
        (should (= (mysql-result-warnings (mysql-fetch cursor 10)) 7))
        (should (= (mysql-conn-status-flags conn) status))
        (should (mysql-in-transaction-p conn))
        (should-not (mysql-autocommit-p conn))
        (should (eq (mysql-cursor-exhausted-p cursor) (= status 129)))))))

(ert-deftest mysql-test-parse-eof-packet ()
  "Test EOF packet status parsing."
  (let ((info (mysql--parse-eof-packet
               (unibyte-string #xfe #x02 #x00 #x80 #x00))))
    (should (= (plist-get info :warnings) 2))
    (should (= (plist-get info :status-flags)
               mysql--server-status-last-row-sent))))

(ert-deftest mysql-test-connection-state-accessors ()
  "Test public connection state accessors."
  (let ((conn (make-mysql-conn :host "localhost" :port 3306
                               :user "root" :database "test"
                               :connection-id 123 :busy t)))
    (should-not (mysql-live-p conn))
    (should (mysql-busy-p conn))
    ;; Library defaults callers rely on.
    (should (= (mysql-conn-read-idle-timeout conn) 30))
    (should (= (mysql-conn-sequence-id conn) 0))
    (should (= (mysql-connection-id conn) 123))
    (should (equal (mysql-connection-user conn) "root"))
    (should (equal (mysql-connection-host conn) "localhost"))
    (should (= (mysql-connection-port conn) 3306))
    (should (equal (mysql-current-database conn) "test"))))

(ert-deftest mysql-test-send-packet-reports-closed-connection ()
  "Sending on a closed process should signal `mysql-connection-error'."
  (let* ((proc (make-process :name "mysql-test-closed"
                             :buffer nil
                             :command (list "cat")))
         (buf (generate-new-buffer " *mysql-test-closed*"))
         (conn (make-mysql-conn :process proc :buf buf)))
    (unwind-protect
        (progn
          (delete-process proc)
          (should-error (mysql--send-packet conn "x")
                        :type 'mysql-connection-error))
      (when (process-live-p proc)
        (delete-process proc))
      (when (buffer-live-p buf)
        (kill-buffer buf)))))

(ert-deftest mysql-test-disconnect-cleans-up-after-closed-connection ()
  "Disconnect should still clean up when COM_QUIT sees a closed connection."
  (let ((buf (generate-new-buffer " *mysql-test-disconnect-closed*"))
        deleted)
    (unwind-protect
        (cl-letf (((symbol-function 'process-live-p) (lambda (_proc) t))
                  ((symbol-function 'mysql--send-packet)
                   (lambda (&rest _args)
                     (signal 'mysql-connection-error '("Connection closed"))))
                  ((symbol-function 'delete-process)
                   (lambda (_proc) (setq deleted t))))
          (mysql-disconnect (make-mysql-conn :process 'fake-proc :buf buf))
          (should deleted)
          (should-not (buffer-live-p buf)))
      (when (buffer-live-p buf)
        (kill-buffer buf)))))

(ert-deftest mysql-test-disconnect-propagates-unexpected-send-error ()
  "Disconnect should not swallow non-connection failures from COM_QUIT."
  (let ((buf (generate-new-buffer " *mysql-test-disconnect-error*")))
    (unwind-protect
        (cl-letf (((symbol-function 'process-live-p) (lambda (_proc) t))
                  ((symbol-function 'mysql--send-packet)
                   (lambda (&rest _args)
                     (error "Unexpected write failure"))))
          (should-error
           (mysql-disconnect (make-mysql-conn :process 'fake-proc :buf buf))
           :type 'error))
      (when (buffer-live-p buf)
        (kill-buffer buf)))))

(ert-deftest mysql-test-select-database-updates-cache-after-use ()
  "Test `mysql-select-database' updates CONN after a successful USE."
  (let ((conn (make-mysql-conn :database "old"))
        observed-sql)
    (cl-letf (((symbol-function 'mysql-query)
               (lambda (mysql-conn sql)
                 (should (eq mysql-conn conn))
                 (setq observed-sql sql)
                 (make-mysql-result :connection mysql-conn :status "OK"))))
      (should (equal (mysql-select-database conn " app`db ") "app`db"))
      (should (equal observed-sql "USE `app``db`"))
      (should (equal (mysql-current-database conn) "app`db")))))

(ert-deftest mysql-test-drain-query-response-restores-timeout-and-busy ()
  "Draining a response should mark CONN busy and restore its timeout."
  (let ((conn (make-mysql-conn :read-idle-timeout 30
                               :response-pending t))
        observed-timeout
        observed-busy
        observed-packet)
    (cl-letf (((symbol-function 'mysql--read-packet)
               (lambda (mysql-conn)
                 (should (eq mysql-conn conn))
                 (setq observed-timeout (mysql-conn-read-idle-timeout mysql-conn)
                       observed-busy (mysql-conn-busy mysql-conn))
                 "packet"))
              ((symbol-function 'mysql--handle-query-response)
               (lambda (mysql-conn packet)
                 (should (eq mysql-conn conn))
                 (setq observed-packet packet)
                 (make-mysql-result :connection mysql-conn :status "OK"))))
      (should (mysql-drain-query-response conn 0.25))
      (should (equal observed-packet "packet"))
      (should (= observed-timeout 0.25))
      (should observed-busy)
      (should-not (mysql-conn-busy conn))
      (should-not (mysql-conn-response-pending conn))
      (should (= (mysql-conn-read-idle-timeout conn) 30)))))

(ert-deftest mysql-test-drain-query-response-propagates-query-error ()
  "Draining should consume an ERR response but still signal `mysql-query-error'."
  (let ((conn (make-mysql-conn :read-idle-timeout 30
                               :response-pending t))
        drained)
    (cl-letf (((symbol-function 'mysql--read-packet)
               (lambda (_conn) "err-packet"))
              ((symbol-function 'mysql--handle-query-response)
               (lambda (_conn packet)
                 (should (equal packet "err-packet"))
                 (setq drained t)
                 (signal 'mysql-query-error '("[1317] Query execution was interrupted")))))
      (should-error (mysql-drain-query-response conn 0.25)
                    :type 'mysql-query-error)
      (should drained)
      (should-not (mysql-conn-busy conn))
      (should-not (mysql-conn-response-pending conn))
      (should (= (mysql-conn-read-idle-timeout conn) 30)))))

(ert-deftest mysql-test-timeout-blocks-commands-until-response-is-drained ()
  "A timed-out command should leave CONN reserved for response draining."
  (let ((conn (make-mysql-conn))
        called)
    (should-error
     (mysql--run-command-response
      conn "query"
      (lambda ()
        (setf (mysql-conn-response-drainable conn) t)
        (signal 'mysql-timeout '("timed out"))))
     :type 'mysql-timeout)
    (should (mysql-conn-response-pending conn))
    (should-not (mysql-conn-busy conn))
    (should-error
     (mysql--run-command-response conn "next query"
                                  (lambda () (setq called t)))
     :type 'mysql-error)
    (should-not called)))

(defmacro mysql-test--with-pipe-conn (var &rest body)
  "Run BODY with VAR bound to a `mysql-conn' over a fresh pipe process.
The process and its buffer are cleaned up afterwards."
  (declare (indent 1) (debug (symbolp body)))
  (let ((buf (make-symbol "buffer"))
        (proc (make-symbol "process")))
    `(let* ((,buf (generate-new-buffer " *mysql-test-conn*"))
            (,proc (make-pipe-process :name "mysql-test-conn"
                                      :buffer ,buf :noquery t))
            (,var (make-mysql-conn :process ,proc :buf ,buf)))
       (unwind-protect
           (progn ,@body)
         (when (process-live-p ,proc)
           (delete-process ,proc))
         (when (buffer-live-p ,buf)
           (kill-buffer ,buf))))))

(ert-deftest mysql-test-command-interruption-matrix ()
  "Every command abandonment closes or preserves by where the stream stopped.
A boundary exit -- nothing of the response consumed yet -- preserves the
connection for the out-of-band cancel-and-drain path.  A mid-response
exit closes it: the stream position is inside the response, and a later
drain would read a row as a response header.  Query and statement
errors are boundary by construction, since their ERR or OK packet is
fully consumed before the signal, so they keep the connection usable
without a pending drain."
  (dolist (case '((timeout     t   preserve)
                  (timeout     nil close)
                  (quit        t   preserve)
                  (quit        nil close)
                  (throw       t   preserve)
                  (throw       nil close)
                  (query-error nil usable)
                  (stmt-error  nil usable)))
    (pcase-let ((`(,exit ,drainable ,expected) case))
      (ert-info ((format "exit: %s drainable: %s" exit drainable))
        (mysql-test--with-pipe-conn conn
          (let ((run (lambda ()
                       (mysql--run-command-response
                        conn "query"
                        (lambda ()
                          (setf (mysql-conn-response-drainable conn)
                                drainable)
                          (pcase exit
                            ('timeout (signal 'mysql-timeout '("timed out")))
                            ('quit (signal 'quit nil))
                            ('throw (throw 'mysql-test-exit :aborted))
                            ('query-error
                             (signal 'mysql-query-error '("[1064] boom")))
                            ('stmt-error
                             (signal 'mysql-stmt-error '("[1210] boom")))))))))
            (pcase exit
              ('quit
               (let (caught)
                 (condition-case nil (funcall run) (quit (setq caught t)))
                 (should caught)))
              ('throw
               (should (eq (catch 'mysql-test-exit (funcall run)) :aborted)))
              (_
               (should-error (funcall run)
                             :type (pcase exit
                                     ('timeout 'mysql-timeout)
                                     ('query-error 'mysql-query-error)
                                     ('stmt-error 'mysql-stmt-error))))))
          (should-not (mysql-conn-busy conn))
          (pcase expected
            ('preserve
             (should (mysql-live-p conn))
             (should (mysql-conn-response-pending conn)))
            ('close
             (should-not (mysql-live-p conn))
             (should-not (buffer-live-p (mysql-conn-buf conn)))
             (should-not (mysql-conn-response-pending conn)))
            ('usable
             (should (mysql-live-p conn))
             (should-not (mysql-conn-response-pending conn)))))))))

(ert-deftest mysql-test-drain-interruption-follows-consumption ()
  "A drain abandoned mid-response closes CONN; at the boundary it retries.
Consumed packets are gone, so a second drain would read the remainder of
the pending response as a fresh one; a partial packet read restores its
offsets and consumes nothing, which keeps the boundary case retryable."
  (dolist (case '((consumed close) (boundary retry)))
    (pcase-let ((`(,progress ,expected) case))
      (ert-info ((format "progress: %s" progress))
        (mysql-test--with-pipe-conn conn
          (setf (mysql-conn-response-pending conn) t)
          (let (caught)
            (cl-letf (((symbol-function 'mysql--read-packet)
                       (lambda (conn)
                         (when (eq progress 'consumed)
                           (cl-incf (mysql-conn-response-bytes conn) 9))
                         (signal 'quit nil))))
              (condition-case nil
                  (mysql-drain-query-response conn)
                (quit (setq caught t))))
            (should caught))
          (pcase expected
            ('close
             (should-not (mysql-live-p conn))
             (should-not (buffer-live-p (mysql-conn-buf conn))))
            ('retry
             (should (mysql-live-p conn))
             (should (mysql-conn-response-pending conn)))))))))

(ert-deftest mysql-test-read-packet-timeout-restores-packet-offset ()
  "A partial packet read should be restartable by response draining."
  (mysql-test--with-pipe-conn conn
    (setf (mysql-conn-read-idle-timeout conn) 0
          (mysql-conn-sequence-id conn) 9)
    (with-current-buffer (mysql-conn-buf conn)
      (set-buffer-multibyte nil)
      (insert (unibyte-string 3 0 0 9 ?x)))
    (should-error (mysql--read-packet conn) :type 'mysql-timeout)
    (should (= (mysql-conn-read-offset conn) 0))
    (should (= (mysql-conn-sequence-id conn) 9))))

(ert-deftest mysql-test-drain-query-response-rejects-invalid-preconditions ()
  "Draining requires an idle CONN with an actual pending response."
  (ert-info ("busy connection")
    (let ((conn (make-mysql-conn :busy t)))
      (should-error (mysql-drain-query-response conn) :type 'mysql-error)
      (should (mysql-conn-busy conn))))
  (ert-info ("no pending response")
    (should-error (mysql-drain-query-response (make-mysql-conn))
                  :type 'mysql-error)))

(ert-deftest mysql-test-open-connection-does-not-force-plain-type ()
  "Socket setup should not force a process type and must install the sentinel."
  (let (captured-args installed-sentinel)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest args)
                 (setq captured-args args)
                 'fake-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'set-process-filter) #'ignore)
              ((symbol-function 'set-process-sentinel)
               (lambda (_proc sentinel)
                 (setq installed-sentinel sentinel)))
              ((symbol-function 'mysql--wait-for-connect) #'ignore))
      (pcase-let ((`(,proc . ,buf) (mysql--open-connection "127.0.0.1" 3306 10)))
        (unwind-protect
            (progn
              (should (eq proc 'fake-proc))
              (should-not (plist-member captured-args :type))
              ;; The wire-safe sentinel keeps close events out of the buffer.
              (should (eq installed-sentinel #'mysql--process-sentinel)))
          (kill-buffer buf))))))

(ert-deftest mysql-test-open-connection-cleans-buffer-on-create-error ()
  "A socket creation failure should not leak the input buffer."
  (let (buffer)
    (cl-letf (((symbol-function 'generate-new-buffer)
               (lambda (_name)
                 (setq buffer (get-buffer-create " *mysql-test-open-error*"))))
              ((symbol-function 'make-network-process)
               (lambda (&rest _args) (error "connect failed"))))
      (should-error (mysql--open-connection "invalid" 3306 1))
      (should-not (buffer-live-p buffer)))))

(ert-deftest mysql-test-stmt-close-rejects-pending-response ()
  "Statement close should not interleave with a pending response."
  (let* ((conn (make-mysql-conn :response-pending t))
         (stmt (make-mysql-stmt :conn conn :id 1)))
    (should-error (mysql-stmt-close stmt) :type 'mysql-error)))

(defmacro mysql-test--with-auto-tls-stubs (auth-fn tls-flags &rest body)
  "Run BODY with the connect/auth path stubbed for auto-TLS-retry tests.
AUTH-FN plays `mysql--authenticate'; TLS-FLAGS names a variable
collecting the tls argument of each auth attempt in call order."
  (declare (indent 2) (debug (form symbolp body)))
  `(let ((,tls-flags nil)
         (buffers nil))
     (cl-letf (((symbol-function 'gnutls-available-p) (lambda () t))
               ((symbol-function 'mysql--open-connection)
                (lambda (_host _port _timeout)
                  (let ((buf (generate-new-buffer " *mysql-test-auto-tls*")))
                    (push buf buffers)
                    (cons (gensym "proc") buf))))
               ((symbol-function 'mysql--authenticate)
                (lambda (conn password tls)
                  (push tls ,tls-flags)
                  (funcall ,auth-fn conn password tls)))
               ((symbol-function 'process-live-p) (lambda (_proc) t))
               ((symbol-function 'delete-process) (lambda (_proc) nil)))
       (unwind-protect
           (progn ,@body)
         (mapc (lambda (buf)
                 (when (buffer-live-p buf)
                   (kill-buffer buf)))
               buffers)))))

(ert-deftest mysql-test-connect-retries-caching-sha2-full-auth-with-tls ()
  "A non-TLS caching_sha2 full-auth failure should reconnect with TLS."
  (mysql-test--with-auto-tls-stubs
      (lambda (conn _password tls)
        (if tls
            (setf (mysql-conn-tls conn) t)
          (signal 'mysql-auth-error
                  '("caching_sha2_password full authentication requires TLS"))))
      auth-tls-flags
    (let ((conn (mysql-connect :host "127.0.0.1" :port 3306
                               :user "root" :password "pw"
                               :database "mysql")))
      (should (equal (nreverse auth-tls-flags) '(nil t)))
      (should (mysql-conn-tls conn)))))

(ert-deftest mysql-test-connect-tls-opt-outs-disable-auto-tls-retry ()
  "Every TLS opt-out spelling keeps MySQL 8 auth plaintext and fails loudly."
  (dolist (extra-args '((:ssl-mode disabled)
                        (:ssl-mode off)
                        (:tls nil)))
    (ert-info ((format "connect args: %s" extra-args))
      (mysql-test--with-auto-tls-stubs
          (lambda (_conn _password _tls)
            (signal 'mysql-auth-error
                    '("caching_sha2_password full authentication requires TLS")))
          auth-tls-flags
        (should-error
         (apply #'mysql-connect
                :host "127.0.0.1" :port 3306
                :user "root" :password "pw" :database "mysql"
                extra-args)
         :type 'mysql-auth-error)
        (should (equal auth-tls-flags '(nil)))))))

(ert-deftest mysql-test-connect-rejects-invalid-tls-options ()
  "Conflicting or unknown TLS options should fail before connecting."
  (dolist (extra-args '((:tls t :ssl-mode disabled)
                        (:ssl-mode required)))
    (ert-info ((format "extra args: %s" extra-args))
      (should-error (apply #'mysql-connect
                           :host "127.0.0.1" :port 3306
                           :user "root" :password "pw"
                           :database "mysql" extra-args)
                    :type 'mysql-connection-error))))

;;;; Protocol hardening regressions

(ert-deftest mysql-test-binary-row-uses-full-column-metadata ()
  "Binary rows should honor signedness and decode typed strings."
  (let* ((utf8 (encode-coding-string "中文" 'utf-8))
         (json (encode-coding-string "{\"x\":1}" 'utf-8))
         (columns (list (list :type mysql-type-long :flags 0)
                        (list :type mysql-type-long
                              :flags mysql--column-flag-unsigned)
                        (list :type mysql-type-var-string :flags 0
                              :character-set 45)
                        (list :type mysql-type-bit :flags 0
                              :character-set mysql--binary-character-set)
                        (list :type mysql-type-newdecimal :flags 0
                              :character-set 45)
                        (list :type mysql-type-json :flags 0
                              :character-set 45)))
         (packet (concat (unibyte-string 0 0)
                         (mysql--int-le-bytes #xffffffff 4)
                         (mysql--int-le-bytes #xffffffff 4)
                         (mysql--lenenc-int-bytes (length utf8)) utf8
                         (unibyte-string 2 1 0)
                         (unibyte-string 4) "12.5"
                         (mysql--lenenc-int-bytes (length json)) json))
         (row (mysql--parse-binary-row packet columns)))
    (should (= (nth 0 row) -1))
    (should (= (nth 1 row) #xffffffff))
    (should (equal (nth 2 row) "中文"))
    (should (= (nth 3 row) 256))
    ;; DECIMAL keeps its exact digit string; a float cannot represent
    ;; every value the type exists to keep exact.
    (should (equal (nth 4 row) "12.5"))
    (should (= (gethash "x" (nth 5 row)) 1))))

(ert-deftest mysql-test-binary-blob-type-respects-character-set ()
  "BLOB wire types should still decode textual columns by character set."
  (let ((value (encode-coding-string "中文" 'utf-8)))
    (should
     (equal (mysql--parse-typed-value
             value mysql-type-blob
             (list :type mysql-type-blob :flags 0 :character-set 45))
            "中文"))
    (should
     (equal (mysql--parse-typed-value
             value mysql-type-blob
             (list :type mysql-type-blob :flags 0
                   :character-set mysql--binary-character-set))
            value))))

(ert-deftest mysql-test-read-packet-rejects-sequence-mismatch ()
  "Incoming fragments must match the expected packet sequence."
  (mysql-test--with-pipe-conn conn
    (setf (mysql-conn-sequence-id conn) 3)
    (with-current-buffer (mysql-conn-buf conn)
      (set-buffer-multibyte nil)
      (insert (unibyte-string 1 0 0 4 ?x)))
    (should-error (mysql--read-packet conn) :type 'mysql-protocol-error)
    (should-not (mysql-live-p conn))
    (should-not (buffer-live-p (mysql-conn-buf conn)))))

(ert-deftest mysql-test-remote-close-keeps-final-err-packet-readable ()
  "A peer close must not corrupt an ERR packet buffered just before it.
MySQL sends its last ERR -- Access denied, shutdown -- and closes; the
default sentinel would insert its event text at the process mark, ahead
of those bytes, and the parser would read prose as a packet header."
  (mysql-test--with-pipe-conn conn
    (let ((proc (mysql-conn-process conn))
          (payload (concat (unibyte-string #xff #x15 #x04) "#28000"
                           "Access denied")))
      (set-process-sentinel proc #'mysql--process-sentinel)
      (setf (mysql-conn-sequence-id conn) 2)
      (with-current-buffer (mysql-conn-buf conn)
        (set-buffer-multibyte nil)
        (insert (mysql--int-le-bytes (length payload) 3)
                (unibyte-string 2)
                payload))
      ;; The remote peer closes after sending its final packet.
      (delete-process proc)
      (accept-process-output nil 0.05)
      (should (process-get proc 'mysql-error))
      (let ((packet (mysql--read-packet conn)))
        (should (eq (mysql--packet-type packet) 'err))
        (let ((err (mysql--parse-err-packet packet)))
          (should (= (plist-get err :code) 1045))
          (should (equal (plist-get err :message) "Access denied")))))))

(ert-deftest mysql-test-read-packet-enforces-message-and-response-limits ()
  "Logical packet and command response byte budgets should be bounded."
  (dolist (limits '((2 100) (100 2)))
    (ert-info ((format "limits: %s" limits))
      (mysql-test--with-pipe-conn conn
        (with-current-buffer (mysql-conn-buf conn)
          (set-buffer-multibyte nil)
          (insert (unibyte-string 3 0 0 0 ?a ?b ?c)))
        (let ((mysql-max-message-bytes (car limits))
              (mysql-max-response-bytes (cadr limits)))
          (should-error (mysql--read-packet conn) :type 'mysql-protocol-error))
        (should-not (mysql-live-p conn))
        (should-not (buffer-live-p (mysql-conn-buf conn)))))))

(ert-deftest mysql-test-auth-response-fails-closed ()
  "Unknown and incomplete authentication packets should be rejected."
  (dolist (packet (list "" (unibyte-string #x02) (unibyte-string #x01)))
    (cl-letf (((symbol-function 'mysql--read-packet)
               (lambda (_conn) packet)))
      (should-error
       (mysql--handle-auth-response (make-mysql-conn) "pw" "salt"
                                    "caching_sha2_password")
       :type 'mysql-auth-error))))

(ert-deftest mysql-test-result-parse-error-invalidates-connection ()
  "A structural error mid-response must make the stream unusable."
  (mysql-test--with-pipe-conn conn
    (setf (mysql-conn-capability-flags conn) 0)
    (cl-letf (((symbol-function 'mysql--send-packet) #'ignore)
              ((symbol-function 'mysql--read-packet)
               (lambda (_conn) (unibyte-string 1))))
      (should-error (mysql-query conn "SELECT 1")))
    (should-not (mysql-live-p conn))
    (should-not (buffer-live-p (mysql-conn-buf conn)))))

(ert-deftest mysql-test-binary-row-parse-error-invalidates-connection ()
  "A malformed prepared-row response must invalidate the stream."
  (mysql-test--with-pipe-conn conn
    (let ((cursor (make-mysql-cursor
                   :stmt (make-mysql-stmt :conn conn :id 1)
                   :columns (list (list :type mysql-type-longlong :flags 0)))))
      (cl-letf (((symbol-function 'mysql--send-packet) #'ignore)
                ((symbol-function 'mysql--read-packet)
                 (lambda (_conn) (unibyte-string 0 0))))
        (should-error (mysql-fetch cursor 1))))
    (should-not (mysql-live-p conn))
    (should-not (buffer-live-p (mysql-conn-buf conn)))))

;;;; Live integration tests (require a running MySQL server)

(defmacro mysql-test--with-conn (var &rest body)
  "Execute BODY with VAR bound to a live MySQL connection.
Skips if `mysql-test-password' is nil."
  (declare (indent 1))
  `(if (null mysql-test-password)
       (ert-skip "Set mysql-test-password to enable live tests")
     (let ((mysql-tls-verify-server nil))
       (let ((,var (mysql-connect :host mysql-test-host
                                  :port mysql-test-port
                                  :user mysql-test-user
                                  :password mysql-test-password
                                  :database mysql-test-database)))
         (unwind-protect
             (progn ,@body)
           (mysql-disconnect ,var))))))

(ert-deftest mysql-test-live-connect-disconnect ()
  :tags '(:mysql-live)
  "Test connecting and disconnecting."
  (mysql-test--with-conn conn
    (should (mysql-conn-p conn))
    (should (mysql-conn-server-version conn))
    (should (> (mysql-conn-connection-id conn) 0))))

(ert-deftest mysql-test-live-select ()
  :tags '(:mysql-live)
  "Test a simple SELECT query."
  (mysql-test--with-conn conn
    (let ((result (mysql-query conn "SELECT 1 AS num, 'hello' AS greeting")))
      (should (mysql-result-p result))
      (should (equal (mysql-result-status result) "OK"))
      (should (= (length (mysql-result-columns result)) 2))
      (should (= (length (mysql-result-rows result)) 1))
      (let ((row (car (mysql-result-rows result))))
        (should (= (car row) 1))
        (should (equal (cadr row) "hello"))))))

(ert-deftest mysql-test-live-multi-row ()
  :tags '(:mysql-live)
  "Test query returning multiple rows."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_multi_row (id INT, name VARCHAR(20))")
    (mysql-query conn "INSERT INTO _mysql_el_multi_row VALUES (1, 'one'), (2, 'two'), (3, 'three')")
    (let ((result (mysql-query conn "SELECT id, name FROM _mysql_el_multi_row ORDER BY id")))
      (should (mysql-result-p result))
      (should (= (length (mysql-result-rows result)) 3))
      (should (equal (mysql-result-rows result)
                     '((1 "one") (2 "two") (3 "three")))))))

(ert-deftest mysql-test-live-dml ()
  :tags '(:mysql-live)
  "Test INSERT/UPDATE/DELETE (DML) returning affected-rows."
  (mysql-test--with-conn conn
    ;; Create a temp table
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_test (id INT, val VARCHAR(50))")
    (let ((result (mysql-query conn "INSERT INTO _mysql_el_test VALUES (1, 'one'), (2, 'two')")))
      (should (= (mysql-result-affected-rows result) 2)))
    (let ((result (mysql-query conn "UPDATE _mysql_el_test SET val = 'updated' WHERE id = 1")))
      (should (= (mysql-result-affected-rows result) 1)))
    (let ((result (mysql-query conn "SELECT * FROM _mysql_el_test ORDER BY id")))
      (should (= (length (mysql-result-rows result)) 2))
      (should (equal (cadr (car (mysql-result-rows result))) "updated")))
    (let ((result (mysql-query conn "DELETE FROM _mysql_el_test")))
      (should (= (mysql-result-affected-rows result) 2)))))

(ert-deftest mysql-test-live-query-error ()
  :tags '(:mysql-live)
  "Test that a syntax error signals mysql-query-error."
  (mysql-test--with-conn conn
    (should-error (mysql-query conn "SELEC BAD SYNTAX")
                  :type 'mysql-query-error)))

(ert-deftest mysql-test-live-auth-failure ()
  :tags '(:mysql-live)
  "Test that wrong password signals mysql-auth-error."
  (if (null mysql-test-password)
      (ert-skip "Set mysql-test-password to enable live tests")
    (let ((mysql-tls-verify-server nil))
      (should-error (mysql-connect :host mysql-test-host
                                   :port mysql-test-port
                                   :user mysql-test-user
                                   :password "definitely-wrong-password"
                                   :database mysql-test-database)
                    :type 'mysql-auth-error))))

(ert-deftest mysql-test-live-null-values ()
  :tags '(:mysql-live)
  "Test that NULL values are returned as nil."
  (mysql-test--with-conn conn
    (let ((result (mysql-query conn "SELECT NULL AS n, 42 AS v")))
      (let ((row (car (mysql-result-rows result))))
        (should (null (car row)))
        (should (= (cadr row) 42))))))

(ert-deftest mysql-test-live-empty-result ()
  :tags '(:mysql-live)
  "Test a query that returns zero rows."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_empty (id INT)")
    (let ((result (mysql-query conn "SELECT * FROM _mysql_el_empty")))
      (should (= (length (mysql-result-rows result)) 0))
      (should (= (length (mysql-result-columns result)) 1)))))

;;;; Live tests — Extended type system

(ert-deftest mysql-test-live-date-time-types ()
  :tags '(:mysql-live)
  "Test DATE, TIME, DATETIME, TIMESTAMP column parsing."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_dt (
       d DATE, t TIME, dt DATETIME, ts TIMESTAMP NULL)")
    (mysql-query conn "INSERT INTO _mysql_el_dt VALUES
       ('2024-03-15', '13:45:30', '2024-03-15 13:45:30', '2024-03-15 13:45:30')")
    (let* ((result (mysql-query conn "SELECT * FROM _mysql_el_dt"))
           (row (car (mysql-result-rows result))))
      ;; DATE
      (should (equal (nth 0 row) '(:year 2024 :month 3 :day 15)))
      ;; TIME
      (should (equal (nth 1 row) '(:hours 13 :minutes 45 :seconds 30 :negative nil)))
      ;; DATETIME
      (should (= (plist-get (nth 2 row) :year) 2024))
      (should (= (plist-get (nth 2 row) :hours) 13))
      ;; TIMESTAMP
      (should (= (plist-get (nth 3 row) :year) 2024)))))

(ert-deftest mysql-test-live-bit-enum-set ()
  :tags '(:mysql-live)
  "Test BIT, ENUM, SET column parsing."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_bes (
       b BIT(8), e ENUM('a','b','c'), s SET('x','y','z'))")
    (mysql-query conn "INSERT INTO _mysql_el_bes VALUES (b'11111111', 'b', 'x,z')")
    (let* ((result (mysql-query conn "SELECT * FROM _mysql_el_bes"))
           (row (car (mysql-result-rows result))))
      ;; BIT(8) with all bits set = 255
      (should (= (nth 0 row) 255))
      ;; ENUM and SET are returned as strings
      (should (equal (nth 1 row) "b"))
      (should (equal (nth 2 row) "x,z")))))

;;;; Live tests — Convenience APIs

(ert-deftest mysql-test-live-with-connection ()
  :tags '(:mysql-live)
  "Test with-mysql-connection auto-close."
  (if (null mysql-test-password)
      (ert-skip "Set mysql-test-password to enable live tests")
    (let (saved-conn)
      (with-mysql-connection conn (:host mysql-test-host :port mysql-test-port
                                   :user mysql-test-user :password mysql-test-password
                                   :database mysql-test-database)
        (setq saved-conn conn)
        (should (mysql-conn-p conn))
        (should (process-live-p (mysql-conn-process conn))))
      ;; After the macro, the connection should be closed
      (should-not (process-live-p (mysql-conn-process saved-conn))))))

(ert-deftest mysql-test-live-transaction-commit ()
  :tags '(:mysql-live)
  "Test with-mysql-transaction commits on success."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_tx (id INT)")
    (with-mysql-transaction conn
      (mysql-query conn "INSERT INTO _mysql_el_tx VALUES (1)")
      (mysql-query conn "INSERT INTO _mysql_el_tx VALUES (2)"))
    (let ((result (mysql-query conn "SELECT COUNT(*) FROM _mysql_el_tx")))
      (should (= (car (car (mysql-result-rows result))) 2)))))

(ert-deftest mysql-test-live-transaction-rollback ()
  :tags '(:mysql-live)
  "Test with-mysql-transaction rolls back on error."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_tx2 (id INT)")
    (ignore-errors
      (with-mysql-transaction conn
        (mysql-query conn "INSERT INTO _mysql_el_tx2 VALUES (1)")
        (error "Intentional error")))
    (let ((result (mysql-query conn "SELECT COUNT(*) FROM _mysql_el_tx2")))
      (should (= (car (car (mysql-result-rows result))) 0)))))

(ert-deftest mysql-test-live-autocommit-toggle ()
  :tags '(:mysql-live)
  "Test session autocommit toggling and transaction state helpers."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_toggle (id INT)")
    (should (mysql-autocommit-p conn))
    (mysql-set-autocommit conn nil)
    (should-not (mysql-autocommit-p conn))
    (should-not (mysql-in-transaction-p conn))
    (mysql-query conn "INSERT INTO _mysql_el_toggle VALUES (1)")
    (should (mysql-in-transaction-p conn))
    (mysql-rollback conn)
    (should-not (mysql-in-transaction-p conn))
    (should-not (mysql-autocommit-p conn))
    (let ((result (mysql-query conn "SELECT COUNT(*) FROM _mysql_el_toggle")))
      (should (= (car (car (mysql-result-rows result))) 0)))
    (mysql-set-autocommit conn t)
    (should (mysql-autocommit-p conn))
    (should-not (mysql-in-transaction-p conn))))

(ert-deftest mysql-test-live-ping ()
  :tags '(:mysql-live)
  "Test COM_PING."
  (mysql-test--with-conn conn
    (should (eq (mysql-ping conn) t))))

;;;; Live tests — Prepared statements

(ert-deftest mysql-test-live-prepare-select ()
  :tags '(:mysql-live)
  "Test prepared SELECT with parameters."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn "SELECT ? + ? AS sum")))
      (should (mysql-stmt-p stmt))
      (should (= (mysql-stmt-param-count stmt) 2))
      (let ((result (mysql-execute stmt 10 20)))
        (should (= (length (mysql-result-rows result)) 1))
        (should (= (car (car (mysql-result-rows result))) 30)))
      (mysql-stmt-close stmt))))

(ert-deftest mysql-test-live-prepare-insert ()
  :tags '(:mysql-live)
  "Test prepared INSERT."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_ps (id INT, name VARCHAR(50))")
    (let ((stmt (mysql-prepare conn "INSERT INTO _mysql_el_ps VALUES (?, ?)")))
      (let ((result (mysql-execute stmt 1 "alice")))
        (should (= (mysql-result-affected-rows result) 1)))
      (let ((result (mysql-execute stmt 2 "bob")))
        (should (= (mysql-result-affected-rows result) 1)))
      (mysql-stmt-close stmt))
    (let ((result (mysql-query conn "SELECT * FROM _mysql_el_ps ORDER BY id")))
      (should (= (length (mysql-result-rows result)) 2))
      (should (equal (cadr (car (mysql-result-rows result))) "alice")))))

(ert-deftest mysql-test-live-prepare-null-params ()
  :tags '(:mysql-live)
  "Test prepared statement with NULL parameters."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn "SELECT ? AS v")))
      (let ((result (mysql-execute stmt nil)))
        (should (null (car (car (mysql-result-rows result))))))
      (mysql-stmt-close stmt))))

(ert-deftest mysql-test-live-prepare-string-params ()
  :tags '(:mysql-live)
  "Test prepared statement with string parameters."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn "SELECT CONCAT(?, ?) AS s")))
      (let ((result (mysql-execute stmt "hello" " world")))
        (should (equal (car (car (mysql-result-rows result))) "hello world")))
      (mysql-stmt-close stmt))))

(ert-deftest mysql-test-live-prepare-multiple-executions ()
  :tags '(:mysql-live)
  "Test multiple executions of the same prepared statement."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn "SELECT ? * 2 AS doubled")))
      (dotimes (i 5)
        (let ((result (mysql-execute stmt (1+ i))))
          (should (= (car (car (mysql-result-rows result))) (* (1+ i) 2)))))
      (mysql-stmt-close stmt))))

(ert-deftest mysql-test-live-prepare-cursor-fetch ()
  :tags '(:mysql-live)
  "Test server-side prepared statement cursor fetch."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn
                  "SELECT ? AS n UNION ALL SELECT ? AS n ORDER BY n"))
          cursor)
      (unwind-protect
          (progn
            (setq cursor (mysql-execute-cursor stmt 1 2))
            (let ((first (mysql-fetch cursor 1)))
              (should (equal (mysql-result-rows first) '((1))))
              (should-not (mysql-cursor-exhausted-p cursor)))
            (let ((second (mysql-fetch cursor 1)))
              (should (equal (mysql-result-rows second) '((2)))))
            (let ((done (mysql-fetch cursor 1)))
              (should-not (mysql-result-rows done))
              (should (mysql-cursor-exhausted-p cursor))))
        (when cursor
          (mysql-cursor-close cursor))
        (mysql-stmt-close stmt)))))

(ert-deftest mysql-test-live-prepare-binary-types ()
  :tags '(:mysql-live)
  "Test binary protocol type round-trips."
  (mysql-test--with-conn conn
    (mysql-query conn "CREATE TEMPORARY TABLE _mysql_el_bt (
       i INT, f DOUBLE, s VARCHAR(100), d DATE, dt DATETIME)")
    (let ((stmt (mysql-prepare conn
                  "INSERT INTO _mysql_el_bt VALUES (?, ?, ?, '2024-03-15', '2024-03-15 10:30:00')")))
      (mysql-execute stmt 42 3.14 "hello")
      (mysql-stmt-close stmt))
    (let ((result (mysql-query conn "SELECT * FROM _mysql_el_bt")))
      (let ((row (car (mysql-result-rows result))))
        (should (= (nth 0 row) 42))
        ;; Float comes back via text protocol
        (should (< (abs (- (nth 1 row) 3.14)) 0.001))
        (should (equal (nth 2 row) "hello"))))))

;;;; Live tests — TLS (require mysql-test-tls-enabled)

(defmacro mysql-test--with-tls-conn (var &rest body)
  "Execute BODY with VAR bound to a TLS MySQL connection.
Skips unless both `mysql-test-password' and
`mysql-test-tls-enabled' are set."
  (declare (indent 1))
  `(if (or (null mysql-test-password) (null mysql-test-tls-enabled))
       (ert-skip "Set mysql-test-password and mysql-test-tls-enabled for TLS tests")
     (let ((mysql-tls-verify-server nil))
       (let ((,var (mysql-connect :host mysql-test-host
                                  :port mysql-test-port
                                  :user mysql-test-user
                                  :password mysql-test-password
                                  :database mysql-test-database
                                  :tls t)))
         (unwind-protect
             (progn ,@body)
           (mysql-disconnect ,var))))))

(ert-deftest mysql-test-live-tls-connect ()
  :tags '(:mysql-live :mysql-tls)
  "Test TLS connection and verify encryption is active."
  (mysql-test--with-tls-conn conn
    (should (mysql-conn-tls conn))
    (let* ((result (mysql-query conn "SHOW STATUS LIKE 'Ssl_cipher'"))
           (cipher (cadr (car (mysql-result-rows result)))))
      (should (stringp cipher))
      (should (not (string-empty-p cipher))))))

(ert-deftest mysql-test-live-tls-query-and-prepared ()
  :tags '(:mysql-live :mysql-tls)
  "Test plain query execution and prepared statements over TLS."
  (mysql-test--with-tls-conn conn
    (ert-info ("plain query")
      (let* ((result (mysql-query conn "SELECT 42 AS v, 'tls-ok' AS msg"))
             (row (car (mysql-result-rows result))))
        (should (= (car row) 42))
        (should (equal (cadr row) "tls-ok"))))
    (ert-info ("prepared statement")
      (let ((stmt (mysql-prepare conn "SELECT ? + 1 AS v")))
        (should (= (car (car (mysql-result-rows (mysql-execute stmt 99)))) 100))
        (mysql-stmt-close stmt)))))

(ert-deftest mysql-test-live-caching-sha2-full-auth-requires-tls ()
  :tags '(:mysql-live :mysql-tls)
  "caching_sha2_password full auth succeeds over TLS, explicit or retried.
Covers both the auth-switch path (explicit `:tls t') and the default
connect's automatic TLS retry."
  (if (or (null mysql-test-password) (null mysql-test-tls-enabled))
      (ert-skip "Set mysql-test-password and mysql-test-tls-enabled for TLS tests")
    (dolist (case '(("_mysql_el_sha2test" :explicit-tls)
                    ("_mysql_el_autoretry" :default-retry)))
      (pcase-let ((`(,user ,mode) case))
        (ert-info ((format "mode: %s" mode))
          (let ((mysql-tls-verify-server nil)
                (created nil))
            ;; Create a caching_sha2_password user and flush to force full auth.
            (let ((admin (mysql-connect :host mysql-test-host
                                        :port mysql-test-port
                                        :user mysql-test-user
                                        :password mysql-test-password
                                        :database mysql-test-database
                                        :tls t)))
              (unwind-protect
                  (progn
                    (condition-case nil
                        (mysql-query admin (format "DROP USER IF EXISTS '%s'@'%%'" user))
                      (mysql-query-error nil))
                    (condition-case err
                        (progn
                          (mysql-query admin
                            (format "CREATE USER '%s'@'%%' IDENTIFIED WITH caching_sha2_password BY 'testpw'" user))
                          (mysql-query admin (format "GRANT ALL ON *.* TO '%s'@'%%'" user))
                          (mysql-query admin "FLUSH PRIVILEGES")
                          (setq created t))
                      (mysql-query-error
                       (ert-skip (format "Server does not support caching_sha2_password: %s"
                                         (cadr err))))))
                (mysql-disconnect admin)))
            ;; Connect as the new user; :explicit-tls forces TLS up front,
            ;; :default-retry relies on the default connect's auto-retry.
            (unwind-protect
                (let ((conn (apply #'mysql-connect
                                   :host mysql-test-host
                                   :port mysql-test-port
                                   :user user
                                   :password "testpw"
                                   :database mysql-test-database
                                   (if (eq mode :explicit-tls) '(:tls t) nil))))
                  (unwind-protect
                      (progn
                        (should (mysql-conn-tls conn))
                        (let ((result (mysql-query conn "SELECT CURRENT_USER()")))
                          (should (string-prefix-p user
                                                   (car (car (mysql-result-rows result)))))))
                    (mysql-disconnect conn)))
              (when created
                (let ((admin (mysql-connect :host mysql-test-host
                                            :port mysql-test-port
                                            :user mysql-test-user
                                            :password mysql-test-password
                                            :database mysql-test-database
                                            :tls t)))
                  (unwind-protect
                      (condition-case nil
                          (mysql-query admin (format "DROP USER IF EXISTS '%s'@'%%'" user))
                        (mysql-query-error nil))
                    (mysql-disconnect admin)))))))))))

(ert-deftest mysql-test-execute-integer-boundaries ()
  "Prepared parameters preserve signed and unsigned 64-bit integers."
  (dolist (value (list (- (ash 1 63)) -1 0 (1- (ash 1 63))
                       (ash 1 63) (1- (ash 1 64))))
    (let* ((conn (make-mysql-conn))
           (stmt (make-mysql-stmt :conn conn :id 7 :param-count 1))
           packet)
      (cl-letf (((symbol-function 'mysql--send-packet)
                 (lambda (_conn bytes) (setq packet bytes)))
                ((symbol-function 'mysql--read-packet)
                 (lambda (_conn) (unibyte-string 0 0 0 2 0 0 0))))
        (mysql-execute stmt value))
      (let ((unsigned (not (zerop (logand (aref packet 13) #x80))))
            (raw (mysql--read-le-uint packet 14 8)))
        (should (= (mysql--signed-integer raw 8 unsigned) value))))))

(ert-deftest mysql-test-execute-rejects-out-of-range-integers-before-send ()
  "Unrepresentable integers never reach the transport."
  (dolist (value (list (1- (- (ash 1 63))) (ash 1 64)))
    (let* ((conn (make-mysql-conn))
           (stmt (make-mysql-stmt :conn conn :id 7 :param-count 1))
           sent)
      (cl-letf (((symbol-function 'mysql--send-packet)
                 (lambda (&rest _) (setq sent t)))
                ((symbol-function 'mysql--read-packet)
                 (lambda (_conn) (unibyte-string 0 0 0 2 0 0 0))))
        (should-error (mysql-execute stmt value) :type 'mysql-stmt-error))
      (should-not sent))))

(ert-deftest mysql-test-connect-abandonment-cleans-auth-transport ()
  "Quit and throw during authentication release the opened transport."
  (dolist (exit '(quit throw))
    (mysql-test--with-pipe-conn conn
      (let ((proc (mysql-conn-process conn))
            (buf (mysql-conn-buf conn))
            caught)
        (cl-letf (((symbol-function 'mysql--open-connection)
                   (lambda (&rest _) (cons proc buf)))
                  ((symbol-function 'mysql--authenticate)
                   (lambda (&rest _)
                     (pcase exit
                       ('quit (signal 'quit nil))
                       ('throw (throw 'mysql-test-exit :aborted))))))
          (setq caught
                (catch 'mysql-test-exit
                  (condition-case nil
                      (mysql-connect :user "audit")
                    (quit :aborted)))))
        (should (eq caught :aborted))
        (should-not (process-live-p proc))
        (should-not (buffer-live-p buf))))))

(ert-deftest mysql-test-live-prepared-integer-boundaries ()
  :tags '(:mysql-live)
  "A real prepared statement round-trips signed and unsigned boundaries."
  (mysql-test--with-conn conn
    (let ((stmt (mysql-prepare conn "SELECT ? AS boundary")))
      (unwind-protect
          (dolist (value (list (- (ash 1 63)) -1 0 (1- (ash 1 63))
                               (ash 1 63) (1- (ash 1 64)) -1))
            (should (equal (mysql-result-rows (mysql-execute stmt value))
                           (list (list value)))))
        (mysql-stmt-close stmt)))))

;;; mysql-test.el ends here
