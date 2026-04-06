;;; mysql-wire-test.el --- ERT tests for the MySQL wire protocol client -*- lexical-binding: t; -*-

;; Author: Lucius Chen <chenyh572@gmail.com>
;; Maintainer: Lucius Chen <chenyh572@gmail.com>
;; URL: https://github.com/LuciusChen/mysql.el

;;; Commentary:

;; ERT tests for the MySQL client.
;;
;; Tests marked with :mysql-wire-live require a running MySQL instance:
;;   docker run -e MYSQL_ROOT_PASSWORD=test -p 3306:3306 mysql:8
;;
;; Run all unit tests:
;;   emacs -batch -L .. -l ert -l mysql-wire-test -f ert-run-tests-batch-and-exit
;;
;; Run live integration tests:
;;   emacs -batch -L .. -l ert -l mysql-wire-test \
;;     --eval '(setq mysql-wire-test-password "test")' \
;;     -f ert-run-tests-batch-and-exit

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'mysql-wire)

;;;; Test configuration for live tests

(defvar mysql-wire-test-host "127.0.0.1")
(defvar mysql-wire-test-port 3306)
(defvar mysql-wire-test-user "root")
(defvar mysql-wire-test-password nil
  "Set this to enable live integration tests.")
(defvar mysql-wire-test-database "mysql")
(defvar mysql-wire-test-tls-enabled nil
  "Set this to enable TLS live tests.")

;;;; Unit tests — protocol helpers (no server needed)

(ert-deftest mysql-wire-test-int-le-bytes ()
  "Test little-endian integer encoding."
  (should (equal (mysql-wire--int-le-bytes 0 1) (unibyte-string 0)))
  (should (equal (mysql-wire--int-le-bytes 255 1) (unibyte-string 255)))
  (should (equal (mysql-wire--int-le-bytes #x0102 2) (unibyte-string #x02 #x01)))
  (should (equal (mysql-wire--int-le-bytes #x010203 3) (unibyte-string #x03 #x02 #x01)))
  (should (equal (mysql-wire--int-le-bytes #x01020304 4)
                 (unibyte-string #x04 #x03 #x02 #x01))))

(ert-deftest mysql-wire-test-lenenc-int-bytes ()
  "Test length-encoded integer encoding."
  (should (equal (mysql-wire--lenenc-int-bytes 0) (unibyte-string 0)))
  (should (equal (mysql-wire--lenenc-int-bytes 250) (unibyte-string 250)))
  (should (equal (mysql-wire--lenenc-int-bytes 251)
                 (concat (unibyte-string #xfc) (mysql-wire--int-le-bytes 251 2))))
  (should (equal (mysql-wire--lenenc-int-bytes #xffff)
                 (concat (unibyte-string #xfc) (mysql-wire--int-le-bytes #xffff 2))))
  (should (equal (mysql-wire--lenenc-int-bytes #x10000)
                 (concat (unibyte-string #xfd) (mysql-wire--int-le-bytes #x10000 3)))))

(ert-deftest mysql-wire-test-lenenc-int-from-string ()
  "Test reading length-encoded integers from a string."
  (should (equal (mysql-wire--read-lenenc-int-from-string (unibyte-string 42) 0)
                 '(42 . 1)))
  (should (equal (mysql-wire--read-lenenc-int-from-string
                  (unibyte-string #xfc #x01 #x00) 0)
                 '(1 . 3)))
  (should (equal (mysql-wire--read-lenenc-int-from-string
                  (unibyte-string #xfd #x01 #x00 #x00) 0)
                 '(1 . 4))))

(ert-deftest mysql-wire-test-read-lenenc-string-from-string ()
  "Test reading length-encoded strings."
  (should (equal (mysql-wire--read-lenenc-string-from-string
                  (concat (unibyte-string 5) "hello") 0)
                 '("hello" . 6)))
  (should (equal (mysql-wire--read-lenenc-string-from-string
                  (concat (unibyte-string 0)) 0)
                 '("" . 1))))

(ert-deftest mysql-wire-test-auth-native-password ()
  "Test mysql_native_password computation."
  ;; Empty password should return empty string
  (should (equal (mysql-wire--auth-native-password "" "12345678901234567890") ""))
  (should (equal (mysql-wire--auth-native-password nil "12345678901234567890") ""))
  ;; Non-empty password returns 20 bytes
  (let ((result (mysql-wire--auth-native-password "secret" "12345678901234567890")))
    (should (= (length result) 20))))

(ert-deftest mysql-wire-test-auth-caching-sha2-password ()
  "Test caching_sha2_password computation."
  (should (equal (mysql-wire--auth-caching-sha2-password "" "12345678901234567890") ""))
  (let ((result (mysql-wire--auth-caching-sha2-password "secret" "12345678901234567890")))
    (should (= (length result) 32))))

(ert-deftest mysql-wire-test-xor-strings ()
  "Test XOR of two strings."
  (should (equal (mysql-wire--xor-strings (unibyte-string #xff #x00 #xaa)
                                     (unibyte-string #xff #xff #x55))
                 (unibyte-string #x00 #xff #xff))))

(ert-deftest mysql-wire-test-parse-ok-packet ()
  "Test OK packet parsing."
  (let* ((packet (concat (unibyte-string #x00  ; OK marker
                                         #x01  ; affected_rows = 1
                                         #x00  ; last_insert_id = 0
                                         #x02 #x00  ; status_flags
                                         #x00 #x00)))  ; warnings
         (info (mysql-wire--parse-ok-packet packet)))
    (should (= (plist-get info :affected-rows) 1))
    (should (= (plist-get info :last-insert-id) 0))
    (should (= (plist-get info :warnings) 0))))

(ert-deftest mysql-wire-test-parse-err-packet ()
  "Test ERR packet parsing."
  (let* ((packet (concat (unibyte-string #xff          ; ERR marker
                                         #x15 #x04)   ; error code 1045
                         "#"                           ; SQL state marker
                         "28000"                       ; SQL state
                         "Access denied"))
         (info (mysql-wire--parse-err-packet packet)))
    (should (= (plist-get info :code) 1045))
    (should (equal (plist-get info :state) "28000"))
    (should (equal (plist-get info :message) "Access denied"))))

(ert-deftest mysql-wire-test-packet-type ()
  "Test packet type detection."
  (should (eq (mysql-wire--packet-type (unibyte-string #x00)) 'ok))
  (should (eq (mysql-wire--packet-type (unibyte-string #xff)) 'err))
  (should (eq (mysql-wire--packet-type (unibyte-string #xfe)) 'eof))
  (should (eq (mysql-wire--packet-type (unibyte-string #xfb)) 'local-infile))
  (should (eq (mysql-wire--packet-type (unibyte-string #x03 #x01 #x02)) 'data)))

(ert-deftest mysql-wire-test-parse-value ()
  "Test MySQL type conversion."
  (should (= (mysql-wire--parse-value "42" mysql-wire-type-long) 42))
  (should (= (mysql-wire--parse-value "3.14" mysql-wire-type-float) 3.14))
  (should (= (mysql-wire--parse-value "2024" mysql-wire-type-year) 2024))
  (should (equal (mysql-wire--parse-value "hello" mysql-wire-type-var-string) "hello"))
  (should (null (mysql-wire--parse-value nil mysql-wire-type-long))))

;;;; Extended type system tests

(ert-deftest mysql-wire-test-parse-date ()
  "Test DATE string parsing."
  (should (equal (mysql-wire--parse-date "2024-03-15")
                 '(:year 2024 :month 3 :day 15)))
  (should (null (mysql-wire--parse-date "0000-00-00")))
  (should (null (mysql-wire--parse-date ""))))

(ert-deftest mysql-wire-test-parse-time ()
  "Test TIME string parsing."
  (should (equal (mysql-wire--parse-time "13:45:30")
                 '(:hours 13 :minutes 45 :seconds 30 :negative nil)))
  (should (equal (mysql-wire--parse-time "-02:30:00")
                 '(:hours 2 :minutes 30 :seconds 0 :negative t)))
  (should (null (mysql-wire--parse-time ""))))

(ert-deftest mysql-wire-test-parse-datetime ()
  "Test DATETIME/TIMESTAMP string parsing."
  (should (equal (mysql-wire--parse-datetime "2024-03-15 13:45:30")
                 '(:year 2024 :month 3 :day 15
                   :hours 13 :minutes 45 :seconds 30)))
  (should (equal (mysql-wire--parse-datetime "2024-01-01 00:00:00.123456")
                 '(:year 2024 :month 1 :day 1
                   :hours 0 :minutes 0 :seconds 0)))
  (should (null (mysql-wire--parse-datetime "0000-00-00 00:00:00")))
  (should (null (mysql-wire--parse-datetime ""))))

(ert-deftest mysql-wire-test-parse-bit ()
  "Test BIT binary string parsing."
  (should (= (mysql-wire--parse-bit (unibyte-string #x01)) 1))
  (should (= (mysql-wire--parse-bit (unibyte-string #x00 #xff)) 255))
  (should (= (mysql-wire--parse-bit (unibyte-string #x01 #x00)) 256)))

(ert-deftest mysql-wire-test-custom-type-parser ()
  "Test custom type parser override."
  (let ((mysql-wire-type-parsers (list (cons mysql-wire-type-long
                                       (lambda (v) (concat "custom:" v))))))
    (should (equal (mysql-wire--parse-value "42" mysql-wire-type-long) "custom:42")))
  ;; Without override, original behavior
  (should (= (mysql-wire--parse-value "42" mysql-wire-type-long) 42)))

(ert-deftest mysql-wire-test-parse-value-date-types ()
  "Test that parse-value dispatches date/time types correctly."
  (should (equal (mysql-wire--parse-value "2024-03-15" mysql-wire-type-date)
                 '(:year 2024 :month 3 :day 15)))
  (should (equal (mysql-wire--parse-value "13:45:30" mysql-wire-type-time)
                 '(:hours 13 :minutes 45 :seconds 30 :negative nil)))
  (should (equal (mysql-wire--parse-value "2024-03-15 13:45:30" mysql-wire-type-datetime)
                 '(:year 2024 :month 3 :day 15
                   :hours 13 :minutes 45 :seconds 30)))
  (should (equal (mysql-wire--parse-value "2024-03-15 13:45:30" mysql-wire-type-timestamp)
                 '(:year 2024 :month 3 :day 15
                   :hours 13 :minutes 45 :seconds 30))))

;;;; Convenience API unit tests

(ert-deftest mysql-wire-test-escape-identifier ()
  "Test identifier escaping."
  (should (equal (mysql-wire-escape-identifier "table") "`table`"))
  (should (equal (mysql-wire-escape-identifier "my`table") "`my``table`"))
  (should (equal (mysql-wire-escape-identifier "normal_name") "`normal_name`")))

(ert-deftest mysql-wire-test-escape-literal ()
  "Test literal escaping."
  (should (equal (mysql-wire-escape-literal "hello") "'hello'"))
  (should (equal (mysql-wire-escape-literal "it's") "'it\\'s'"))
  (should (equal (mysql-wire-escape-literal "line\nbreak") "'line\\nbreak'"))
  (should (equal (mysql-wire-escape-literal "back\\slash") "'back\\\\slash'")))

(ert-deftest mysql-wire-test-uri-parsing ()
  "Test MySQL URI parsing via regex."
  ;; Test that the regex matches valid URIs
  (should (string-match
           "\\`mysql://\\([^:@]*\\)\\(?::\\([^@]*\\)\\)?@\\([^:/]*\\)\\(?::\\([0-9]+\\)\\)?\\(?:/\\(.*\\)\\)?\\'"
           "mysql://root:pass@localhost:3306/mydb"))
  (should (equal (match-string 1 "mysql://root:pass@localhost:3306/mydb") "root"))
  (should (equal (match-string 2 "mysql://root:pass@localhost:3306/mydb") "pass"))
  (should (equal (match-string 3 "mysql://root:pass@localhost:3306/mydb") "localhost"))
  (should (equal (match-string 4 "mysql://root:pass@localhost:3306/mydb") "3306"))
  (should (equal (match-string 5 "mysql://root:pass@localhost:3306/mydb") "mydb"))
  ;; Without port
  (should (string-match
           "\\`mysql://\\([^:@]*\\)\\(?::\\([^@]*\\)\\)?@\\([^:/]*\\)\\(?::\\([0-9]+\\)\\)?\\(?:/\\(.*\\)\\)?\\'"
           "mysql://root:pass@localhost/mydb"))
  (should (null (match-string 4 "mysql://root:pass@localhost/mydb"))))

;;;; TLS unit tests

(ert-deftest mysql-wire-test-ssl-request-packet ()
  "Test SSL_REQUEST packet structure."
  (let* ((conn (make-mysql-wire-conn :host "localhost" :port 3306
                                :user "root" :database "test"))
         (packet (mysql-wire--build-ssl-request conn)))
    ;; SSL_REQUEST is exactly 32 bytes
    (should (= (length packet) 32))
    ;; Check client flags include SSL capability
    (let ((flags (logior (aref packet 0)
                         (ash (aref packet 1) 8)
                         (ash (aref packet 2) 16)
                         (ash (aref packet 3) 24))))
      (should (not (zerop (logand flags mysql-wire--cap-ssl))))
      (should (not (zerop (logand flags mysql-wire--cap-protocol-41)))))
    ;; Character set byte should be 45 (utf8mb4)
    (should (= (aref packet 8) 45))
    ;; Bytes 9-31 should be zero (filler)
    (let ((all-zero t))
      (dotimes (i 23)
        (unless (= (aref packet (+ 9 i)) 0) (setq all-zero nil)))
      (should all-zero))))

;;;; Prepared statement unit tests

(ert-deftest mysql-wire-test-build-execute-packet ()
  "Test COM_STMT_EXECUTE packet construction."
  (let* ((stmt (make-mysql-wire-stmt :id 1 :param-count 2 :column-count 1
                                :conn nil
                                :param-definitions nil
                                :column-definitions nil))
         (packet (mysql-wire--build-execute-packet stmt '(42 "hello"))))
    ;; First byte: command 0x17
    (should (= (aref packet 0) #x17))
    ;; stmt_id: 4 bytes LE = 1
    (should (= (aref packet 1) 1))
    (should (= (aref packet 2) 0))
    ;; flags: 0x00
    (should (= (aref packet 5) #x00))
    ;; iteration_count: 1
    (should (= (aref packet 6) 1))))

(ert-deftest mysql-wire-test-null-bitmap ()
  "Test NULL bitmap construction in execute packet."
  (let* ((stmt (make-mysql-wire-stmt :id 1 :param-count 3 :column-count 0
                                :conn nil
                                :param-definitions nil
                                :column-definitions nil))
         (packet (mysql-wire--build-execute-packet stmt '(nil 42 nil))))
    ;; NULL bitmap starts at offset 10 (1+4+1+4)
    ;; Params: nil=bit0, 42=bit1, nil=bit2 → bitmap = 0b101 = 5
    (should (= (aref packet 10) 5))))

(ert-deftest mysql-wire-test-elisp-to-wire-type ()
  "Test Elisp to MySQL type mapping."
  (should (= (car (mysql-wire--elisp-to-wire-type nil)) mysql-wire-type-null))
  (should (= (car (mysql-wire--elisp-to-wire-type 42)) mysql-wire-type-longlong))
  (should (= (car (mysql-wire--elisp-to-wire-type 3.14)) mysql-wire-type-var-string))
  (should (= (car (mysql-wire--elisp-to-wire-type "hello")) mysql-wire-type-var-string)))

(ert-deftest mysql-wire-test-ieee754-double ()
  "Test IEEE 754 double decoding."
  ;; 3.14 = 0x40091EB851EB851F in big-endian
  ;; Little-endian: 1F 85 EB 51 B8 1E 09 40
  (let ((data (unibyte-string #x1f #x85 #xeb #x51 #xb8 #x1e #x09 #x40)))
    (should (< (abs (- (mysql-wire--ieee754-double-to-float data 0) 3.14)) 0.0001)))
  ;; 0.0
  (let ((data (make-string 8 0)))
    (should (= (mysql-wire--ieee754-double-to-float data 0) 0.0)))
  ;; 1.0 = 0x3FF0000000000000 → LE: 00 00 00 00 00 00 F0 3F
  (let ((data (unibyte-string #x00 #x00 #x00 #x00 #x00 #x00 #xf0 #x3f)))
    (should (= (mysql-wire--ieee754-double-to-float data 0) 1.0))))

(ert-deftest mysql-wire-test-ieee754-single ()
  "Test IEEE 754 single-precision float decoding."
  ;; 1.0 = 0x3F800000 → LE: 00 00 80 3F
  (let ((data (unibyte-string #x00 #x00 #x80 #x3f)))
    (should (= (mysql-wire--ieee754-single-to-float data 0) 1.0)))
  ;; 0.0
  (let ((data (make-string 4 0)))
    (should (= (mysql-wire--ieee754-single-to-float data 0) 0.0))))

(ert-deftest mysql-wire-test-binary-null-p ()
  "Test NULL bitmap bit checking for binary rows."
  ;; Bitmap with bit 2 set (col 0, offset=2): byte 0 = 0b00000100 = 4
  (should (mysql-wire--binary-null-p (unibyte-string #x04) 0))
  (should-not (mysql-wire--binary-null-p (unibyte-string #x04) 1))
  ;; Bit 3 = col 1: byte 0 = 0b00001000 = 8
  (should (mysql-wire--binary-null-p (unibyte-string #x08) 1)))

(ert-deftest mysql-wire-test-decode-binary-datetime ()
  "Test binary DATETIME decoding."
  ;; Length 0: nil
  (let ((data (unibyte-string 0)))
    (should (null (car (mysql-wire--decode-binary-datetime data 0 mysql-wire-type-datetime)))))
  ;; Length 4: date only
  (let ((data (unibyte-string 4 #xe8 #x07 3 15)))  ; 2024-03-15
    (let ((result (car (mysql-wire--decode-binary-datetime data 0 mysql-wire-type-datetime))))
      (should (= (plist-get result :year) 2024))
      (should (= (plist-get result :month) 3))
      (should (= (plist-get result :day) 15))))
  ;; Length 7: date + time
  (let ((data (unibyte-string 7 #xe8 #x07 3 15 13 45 30)))
    (let ((result (car (mysql-wire--decode-binary-datetime data 0 mysql-wire-type-datetime))))
      (should (= (plist-get result :year) 2024))
      (should (= (plist-get result :hours) 13))
      (should (= (plist-get result :seconds) 30)))))

(ert-deftest mysql-wire-test-decode-binary-time ()
  "Test binary TIME decoding."
  ;; Length 0: zero time
  (let ((data (unibyte-string 0)))
    (let ((result (car (mysql-wire--decode-binary-time data 0))))
      (should (= (plist-get result :hours) 0))
      (should (= (plist-get result :minutes) 0))))
  ;; Length 8: non-negative time, 0 days, 13:45:30
  (let ((data (unibyte-string 8 0 0 0 0 0 13 45 30)))
    (let ((result (car (mysql-wire--decode-binary-time data 0))))
      (should (= (plist-get result :hours) 13))
      (should (= (plist-get result :minutes) 45))
      (should (= (plist-get result :seconds) 30))
      (should-not (plist-get result :negative))))
  ;; Length 8: negative time
  (let ((data (unibyte-string 8 1 0 0 0 0 2 30 0)))
    (let ((result (car (mysql-wire--decode-binary-time data 0))))
      (should (plist-get result :negative)))))

(ert-deftest mysql-wire-test-parse-binary-row ()
  "Test binary row parsing."
  ;; 2 columns, no NULLs: INT=42, STRING="hi"
  ;; Packet: 0x00 (header) + null_bitmap(1 byte) + values
  ;; null bitmap for 2 cols: (2+2+7)/8 = 1 byte, all zeros
  ;; INT (LONGLONG): 42 as 8-byte LE
  ;; STRING: lenenc "hi" = 0x02 "hi"
  (let* ((columns (list (list :type mysql-wire-type-longlong :name "id")
                        (list :type mysql-wire-type-var-string :name "name")))
         (packet (concat (unibyte-string #x00)          ; header
                         (unibyte-string #x00)          ; null bitmap
                         (mysql-wire--int-le-bytes 42 8)     ; INT value
                         (unibyte-string 2) "hi"))      ; STRING value
         (row (mysql-wire--parse-binary-row packet columns)))
    (should (= (nth 0 row) 42))
    (should (equal (nth 1 row) "hi"))))

(ert-deftest mysql-wire-test-parse-result-row ()
  "Test result row parsing."
  ;; Row with two string columns: "hello" and "world"
  (let* ((packet (concat (unibyte-string 5) "hello"
                         (unibyte-string 5) "world"))
         (row (mysql-wire--parse-result-row packet 2)))
    (should (equal row '("hello" "world"))))
  ;; Row with NULL value
  (let* ((packet (concat (unibyte-string #xfb)
                         (unibyte-string 3) "foo"))
         (row (mysql-wire--parse-result-row packet 2)))
    (should (equal row '(nil "foo")))))

(ert-deftest mysql-wire-test-struct-creation ()
  "Test that structs can be created."
  (let ((conn (make-mysql-wire-conn :host "localhost" :port 3306
                               :user "root" :database "test")))
    (should (equal (mysql-wire-conn-host conn) "localhost"))
    (should (= (mysql-wire-conn-port conn) 3306))
    (should (= (mysql-wire-conn-read-idle-timeout conn) 30))
    (should (= (mysql-wire-conn-sequence-id conn) 0)))
  (let ((result (make-mysql-wire-result :status "OK" :affected-rows 5)))
    (should (equal (mysql-wire-result-status result) "OK"))
    (should (= (mysql-wire-result-affected-rows result) 5))))

(ert-deftest mysql-wire-test-open-connection-does-not-force-plain-type ()
  "Opening a MySQL socket should not force an unsupported process type."
  (let (captured-args)
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest args)
                 (setq captured-args args)
                 'fake-proc))
              ((symbol-function 'set-process-coding-system) #'ignore)
              ((symbol-function 'set-process-filter) #'ignore)
              ((symbol-function 'mysql-wire--wait-for-connect) #'ignore))
      (pcase-let ((`(,proc . ,buf) (mysql-wire--open-connection "127.0.0.1" 3306 10)))
        (unwind-protect
            (progn
              (should (eq proc 'fake-proc))
              (should-not (plist-member captured-args :type)))
          (kill-buffer buf))))))

(ert-deftest mysql-wire-test-connect-retries-caching-sha2-full-auth-with-tls ()
  "A non-TLS caching_sha2 full-auth failure should reconnect with TLS."
  (let ((auth-tls-flags nil)
        (buffers nil))
    (cl-letf (((symbol-function 'mysql-wire--tls-available-p) (lambda () t))
              ((symbol-function 'mysql-wire--open-connection)
               (lambda (_host _port _timeout)
                 (let ((buf (generate-new-buffer " *mysql-wire-test-auto-tls*")))
                   (push buf buffers)
                   (cons (gensym "proc") buf))))
              ((symbol-function 'mysql-wire--authenticate)
               (lambda (conn _password tls)
                 (push tls auth-tls-flags)
                 (if tls
                     (setf (mysql-wire-conn-tls conn) t)
                   (signal 'mysql-wire-auth-error
                           '("caching_sha2_password full authentication requires TLS")))))
              ((symbol-function 'process-live-p) (lambda (_proc) t))
              ((symbol-function 'delete-process) (lambda (_proc) nil)))
      (unwind-protect
          (let ((conn (mysql-wire-connect :host "127.0.0.1" :port 3306
                                     :user "root" :password "pw"
                                     :database "mysql")))
            (should (equal (nreverse auth-tls-flags) '(nil t)))
            (should (mysql-wire-conn-tls conn)))
        (mapc (lambda (buf)
                (when (buffer-live-p buf)
                  (kill-buffer buf)))
              buffers)))))

(ert-deftest mysql-wire-test-connect-ssl-mode-disabled-disables-auto-tls-retry ()
  "ssl-mode disabled should keep MySQL 8 auth on plaintext and fail explicitly."
  (let ((auth-tls-flags nil)
        (buffers nil))
    (cl-letf (((symbol-function 'mysql-wire--tls-available-p) (lambda () t))
              ((symbol-function 'mysql-wire--open-connection)
               (lambda (_host _port _timeout)
                 (let ((buf (generate-new-buffer " *mysql-wire-test-ssl-off*")))
                   (push buf buffers)
                   (cons (gensym "proc") buf))))
              ((symbol-function 'mysql-wire--authenticate)
               (lambda (_conn _password tls)
                 (push tls auth-tls-flags)
                 (signal 'mysql-wire-auth-error
                         '("caching_sha2_password full authentication requires TLS"))))
              ((symbol-function 'process-live-p) (lambda (_proc) t))
              ((symbol-function 'delete-process) (lambda (_proc) nil)))
      (unwind-protect
          (should-error
           (mysql-wire-connect :host "127.0.0.1" :port 3306
                          :user "root" :password "pw"
                          :database "mysql" :ssl-mode 'disabled)
           :type 'mysql-wire-auth-error)
        (should (equal auth-tls-flags '(nil)))
        (mapc (lambda (buf)
                (when (buffer-live-p buf)
                  (kill-buffer buf)))
              buffers)))))

(ert-deftest mysql-wire-test-connect-ssl-mode-off-alias-disables-auto-tls-retry ()
  "ssl-mode off should remain accepted as an alias for disabled."
  (let ((auth-tls-flags nil)
        (buffers nil))
    (cl-letf (((symbol-function 'mysql-wire--tls-available-p) (lambda () t))
              ((symbol-function 'mysql-wire--open-connection)
               (lambda (_host _port _timeout)
                 (let ((buf (generate-new-buffer " *mysql-wire-test-ssl-off*")))
                   (push buf buffers)
                   (cons (gensym "proc") buf))))
              ((symbol-function 'mysql-wire--authenticate)
               (lambda (_conn _password tls)
                 (push tls auth-tls-flags)
                 (signal 'mysql-wire-auth-error
                         '("caching_sha2_password full authentication requires TLS"))))
              ((symbol-function 'process-live-p) (lambda (_proc) t))
              ((symbol-function 'delete-process) (lambda (_proc) nil)))
      (unwind-protect
          (should-error
           (mysql-wire-connect :host "127.0.0.1" :port 3306
                          :user "root" :password "pw"
                          :database "mysql" :ssl-mode 'off)
           :type 'mysql-wire-auth-error)
        (should (equal auth-tls-flags '(nil)))
        (mapc (lambda (buf)
                (when (buffer-live-p buf)
                  (kill-buffer buf)))
              buffers)))))

(ert-deftest mysql-wire-test-connect-explicit-tls-nil-disables-auto-tls-retry ()
  "Explicit :tls nil should force plaintext and fail without auto-retry."
  (let ((auth-tls-flags nil)
        (buffers nil))
    (cl-letf (((symbol-function 'mysql-wire--tls-available-p) (lambda () t))
              ((symbol-function 'mysql-wire--open-connection)
               (lambda (_host _port _timeout)
                 (let ((buf (generate-new-buffer " *mysql-wire-test-tls-nil*")))
                   (push buf buffers)
                   (cons (gensym "proc") buf))))
              ((symbol-function 'mysql-wire--authenticate)
               (lambda (_conn _password tls)
                 (push tls auth-tls-flags)
                 (signal 'mysql-wire-auth-error
                         '("caching_sha2_password full authentication requires TLS"))))
              ((symbol-function 'process-live-p) (lambda (_proc) t))
              ((symbol-function 'delete-process) (lambda (_proc) nil)))
      (unwind-protect
          (should-error
           (mysql-wire-connect :host "127.0.0.1" :port 3306
                          :user "root" :password "pw"
                          :database "mysql" :tls nil)
           :type 'mysql-wire-auth-error)
        (should (equal auth-tls-flags '(nil)))
        (mapc (lambda (buf)
                (when (buffer-live-p buf)
                  (kill-buffer buf)))
              buffers)))))

(ert-deftest mysql-wire-test-connect-rejects-conflicting-tls-and-ssl-mode ()
  "Explicit TLS should conflict with ssl-mode disabled."
  (should-error (mysql-wire-connect :host "127.0.0.1" :port 3306
                               :user "root" :password "pw"
                               :database "mysql"
                               :tls t :ssl-mode 'disabled)
                :type 'mysql-wire-connection-error))

(ert-deftest mysql-wire-test-connect-rejects-unknown-ssl-mode ()
  "Unknown ssl-mode values should fail early."
  (should-error (mysql-wire-connect :host "127.0.0.1" :port 3306
                               :user "root" :password "pw"
                               :database "mysql" :ssl-mode 'required)
                :type 'mysql-wire-connection-error))

;;;; Live integration tests (require a running MySQL server)

(defmacro mysql-wire-test--with-conn (var &rest body)
  "Execute BODY with VAR bound to a live MySQL connection.
Skips if `mysql-wire-test-password' is nil."
  (declare (indent 1))
  `(if (null mysql-wire-test-password)
       (ert-skip "Set mysql-wire-test-password to enable live tests")
     (let ((mysql-wire-tls-verify-server nil))
       (let ((,var (mysql-wire-connect :host mysql-wire-test-host
                                  :port mysql-wire-test-port
                                  :user mysql-wire-test-user
                                  :password mysql-wire-test-password
                                  :database mysql-wire-test-database)))
         (unwind-protect
             (progn ,@body)
           (mysql-wire-disconnect ,var))))))

(ert-deftest mysql-wire-test-live-connect-disconnect ()
  :tags '(:mysql-wire-live)
  "Test connecting and disconnecting."
  (mysql-wire-test--with-conn conn
    (should (mysql-wire-conn-p conn))
    (should (mysql-wire-conn-server-version conn))
    (should (> (mysql-wire-conn-connection-id conn) 0))))

(ert-deftest mysql-wire-test-live-select ()
  :tags '(:mysql-wire-live)
  "Test a simple SELECT query."
  (mysql-wire-test--with-conn conn
    (let ((result (mysql-wire-query conn "SELECT 1 AS num, 'hello' AS greeting")))
      (should (mysql-wire-result-p result))
      (should (equal (mysql-wire-result-status result) "OK"))
      (should (= (length (mysql-wire-result-columns result)) 2))
      (should (= (length (mysql-wire-result-rows result)) 1))
      (let ((row (car (mysql-wire-result-rows result))))
        (should (= (car row) 1))
        (should (equal (cadr row) "hello"))))))

(ert-deftest mysql-wire-test-live-multi-row ()
  :tags '(:mysql-wire-live)
  "Test query returning multiple rows."
  (mysql-wire-test--with-conn conn
    (let ((result (mysql-wire-query conn "SELECT user, host FROM user LIMIT 5")))
      (should (mysql-wire-result-p result))
      (should (>= (length (mysql-wire-result-rows result)) 1)))))

(ert-deftest mysql-wire-test-live-dml ()
  :tags '(:mysql-wire-live)
  "Test INSERT/UPDATE/DELETE (DML) returning affected-rows."
  (mysql-wire-test--with-conn conn
    ;; Create a temp table
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_test (id INT, val VARCHAR(50))")
    (let ((result (mysql-wire-query conn "INSERT INTO _mysql_el_test VALUES (1, 'one'), (2, 'two')")))
      (should (= (mysql-wire-result-affected-rows result) 2)))
    (let ((result (mysql-wire-query conn "UPDATE _mysql_el_test SET val = 'updated' WHERE id = 1")))
      (should (= (mysql-wire-result-affected-rows result) 1)))
    (let ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_test ORDER BY id")))
      (should (= (length (mysql-wire-result-rows result)) 2))
      (should (equal (cadr (car (mysql-wire-result-rows result))) "updated")))
    (let ((result (mysql-wire-query conn "DELETE FROM _mysql_el_test")))
      (should (= (mysql-wire-result-affected-rows result) 2)))))

(ert-deftest mysql-wire-test-live-query-error ()
  :tags '(:mysql-wire-live)
  "Test that a syntax error signals mysql-wire-query-error."
  (mysql-wire-test--with-conn conn
    (should-error (mysql-wire-query conn "SELEC BAD SYNTAX")
                  :type 'mysql-wire-query-error)))

(ert-deftest mysql-wire-test-live-auth-failure ()
  :tags '(:mysql-wire-live)
  "Test that wrong password signals mysql-wire-auth-error."
  (if (null mysql-wire-test-password)
      (ert-skip "Set mysql-wire-test-password to enable live tests")
    (let ((mysql-wire-tls-verify-server nil))
      (should-error (mysql-wire-connect :host mysql-wire-test-host
                                   :port mysql-wire-test-port
                                   :user mysql-wire-test-user
                                   :password "definitely-wrong-password"
                                   :database mysql-wire-test-database)
                    :type 'mysql-wire-auth-error))))

(ert-deftest mysql-wire-test-live-null-values ()
  :tags '(:mysql-wire-live)
  "Test that NULL values are returned as nil."
  (mysql-wire-test--with-conn conn
    (let ((result (mysql-wire-query conn "SELECT NULL AS n, 42 AS v")))
      (let ((row (car (mysql-wire-result-rows result))))
        (should (null (car row)))
        (should (= (cadr row) 42))))))

(ert-deftest mysql-wire-test-live-empty-result ()
  :tags '(:mysql-wire-live)
  "Test a query that returns zero rows."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_empty (id INT)")
    (let ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_empty")))
      (should (= (length (mysql-wire-result-rows result)) 0))
      (should (= (length (mysql-wire-result-columns result)) 1)))))

;;;; Live tests — Extended type system

(ert-deftest mysql-wire-test-live-date-time-types ()
  :tags '(:mysql-wire-live)
  "Test DATE, TIME, DATETIME, TIMESTAMP column parsing."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_dt (
       d DATE, t TIME, dt DATETIME, ts TIMESTAMP NULL)")
    (mysql-wire-query conn "INSERT INTO _mysql_el_dt VALUES
       ('2024-03-15', '13:45:30', '2024-03-15 13:45:30', '2024-03-15 13:45:30')")
    (let* ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_dt"))
           (row (car (mysql-wire-result-rows result))))
      ;; DATE
      (should (equal (nth 0 row) '(:year 2024 :month 3 :day 15)))
      ;; TIME
      (should (equal (nth 1 row) '(:hours 13 :minutes 45 :seconds 30 :negative nil)))
      ;; DATETIME
      (should (= (plist-get (nth 2 row) :year) 2024))
      (should (= (plist-get (nth 2 row) :hours) 13))
      ;; TIMESTAMP
      (should (= (plist-get (nth 3 row) :year) 2024)))))

(ert-deftest mysql-wire-test-live-bit-enum-set ()
  :tags '(:mysql-wire-live)
  "Test BIT, ENUM, SET column parsing."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_bes (
       b BIT(8), e ENUM('a','b','c'), s SET('x','y','z'))")
    (mysql-wire-query conn "INSERT INTO _mysql_el_bes VALUES (b'11111111', 'b', 'x,z')")
    (let* ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_bes"))
           (row (car (mysql-wire-result-rows result))))
      ;; BIT(8) with all bits set = 255
      (should (= (nth 0 row) 255))
      ;; ENUM and SET are returned as strings
      (should (equal (nth 1 row) "b"))
      (should (equal (nth 2 row) "x,z")))))

;;;; Live tests — Convenience APIs

(ert-deftest mysql-wire-test-live-with-connection ()
  :tags '(:mysql-wire-live)
  "Test with-mysql-wire-connection auto-close."
  (if (null mysql-wire-test-password)
      (ert-skip "Set mysql-wire-test-password to enable live tests")
    (let (saved-conn)
      (with-mysql-wire-connection conn (:host mysql-wire-test-host :port mysql-wire-test-port
                                   :user mysql-wire-test-user :password mysql-wire-test-password
                                   :database mysql-wire-test-database)
        (setq saved-conn conn)
        (should (mysql-wire-conn-p conn))
        (should (process-live-p (mysql-wire-conn-process conn))))
      ;; After the macro, the connection should be closed
      (should-not (process-live-p (mysql-wire-conn-process saved-conn))))))

(ert-deftest mysql-wire-test-live-transaction-commit ()
  :tags '(:mysql-wire-live)
  "Test with-mysql-wire-transaction commits on success."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_tx (id INT)")
    (with-mysql-wire-transaction conn
      (mysql-wire-query conn "INSERT INTO _mysql_el_tx VALUES (1)")
      (mysql-wire-query conn "INSERT INTO _mysql_el_tx VALUES (2)"))
    (let ((result (mysql-wire-query conn "SELECT COUNT(*) FROM _mysql_el_tx")))
      (should (= (car (car (mysql-wire-result-rows result))) 2)))))

(ert-deftest mysql-wire-test-live-transaction-rollback ()
  :tags '(:mysql-wire-live)
  "Test with-mysql-wire-transaction rolls back on error."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_tx2 (id INT)")
    (ignore-errors
      (with-mysql-wire-transaction conn
        (mysql-wire-query conn "INSERT INTO _mysql_el_tx2 VALUES (1)")
        (error "Intentional error")))
    (let ((result (mysql-wire-query conn "SELECT COUNT(*) FROM _mysql_el_tx2")))
      (should (= (car (car (mysql-wire-result-rows result))) 0)))))

(ert-deftest mysql-wire-test-live-ping ()
  :tags '(:mysql-wire-live)
  "Test COM_PING."
  (mysql-wire-test--with-conn conn
    (should (eq (mysql-wire-ping conn) t))))

;;;; Live tests — Prepared statements

(ert-deftest mysql-wire-test-live-prepare-select ()
  :tags '(:mysql-wire-live)
  "Test prepared SELECT with parameters."
  (mysql-wire-test--with-conn conn
    (let ((stmt (mysql-wire-prepare conn "SELECT ? + ? AS sum")))
      (should (mysql-wire-stmt-p stmt))
      (should (= (mysql-wire-stmt-param-count stmt) 2))
      (let ((result (mysql-wire-execute stmt 10 20)))
        (should (= (length (mysql-wire-result-rows result)) 1))
        (should (= (car (car (mysql-wire-result-rows result))) 30)))
      (mysql-wire-stmt-close stmt))))

(ert-deftest mysql-wire-test-live-prepare-insert ()
  :tags '(:mysql-wire-live)
  "Test prepared INSERT."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_ps (id INT, name VARCHAR(50))")
    (let ((stmt (mysql-wire-prepare conn "INSERT INTO _mysql_el_ps VALUES (?, ?)")))
      (let ((result (mysql-wire-execute stmt 1 "alice")))
        (should (= (mysql-wire-result-affected-rows result) 1)))
      (let ((result (mysql-wire-execute stmt 2 "bob")))
        (should (= (mysql-wire-result-affected-rows result) 1)))
      (mysql-wire-stmt-close stmt))
    (let ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_ps ORDER BY id")))
      (should (= (length (mysql-wire-result-rows result)) 2))
      (should (equal (cadr (car (mysql-wire-result-rows result))) "alice")))))

(ert-deftest mysql-wire-test-live-prepare-null-params ()
  :tags '(:mysql-wire-live)
  "Test prepared statement with NULL parameters."
  (mysql-wire-test--with-conn conn
    (let ((stmt (mysql-wire-prepare conn "SELECT ? AS v")))
      (let ((result (mysql-wire-execute stmt nil)))
        (should (null (car (car (mysql-wire-result-rows result))))))
      (mysql-wire-stmt-close stmt))))

(ert-deftest mysql-wire-test-live-prepare-string-params ()
  :tags '(:mysql-wire-live)
  "Test prepared statement with string parameters."
  (mysql-wire-test--with-conn conn
    (let ((stmt (mysql-wire-prepare conn "SELECT CONCAT(?, ?) AS s")))
      (let ((result (mysql-wire-execute stmt "hello" " world")))
        (should (equal (car (car (mysql-wire-result-rows result))) "hello world")))
      (mysql-wire-stmt-close stmt))))

(ert-deftest mysql-wire-test-live-prepare-multiple-executions ()
  :tags '(:mysql-wire-live)
  "Test multiple executions of the same prepared statement."
  (mysql-wire-test--with-conn conn
    (let ((stmt (mysql-wire-prepare conn "SELECT ? * 2 AS doubled")))
      (dotimes (i 5)
        (let ((result (mysql-wire-execute stmt (1+ i))))
          (should (= (car (car (mysql-wire-result-rows result))) (* (1+ i) 2)))))
      (mysql-wire-stmt-close stmt))))

(ert-deftest mysql-wire-test-live-prepare-binary-types ()
  :tags '(:mysql-wire-live)
  "Test binary protocol type round-trips."
  (mysql-wire-test--with-conn conn
    (mysql-wire-query conn "CREATE TEMPORARY TABLE _mysql_el_bt (
       i INT, f DOUBLE, s VARCHAR(100), d DATE, dt DATETIME)")
    (let ((stmt (mysql-wire-prepare conn
                  "INSERT INTO _mysql_el_bt VALUES (?, ?, ?, '2024-03-15', '2024-03-15 10:30:00')")))
      (mysql-wire-execute stmt 42 3.14 "hello")
      (mysql-wire-stmt-close stmt))
    (let ((result (mysql-wire-query conn "SELECT * FROM _mysql_el_bt")))
      (let ((row (car (mysql-wire-result-rows result))))
        (should (= (nth 0 row) 42))
        ;; Float comes back via text protocol
        (should (< (abs (- (nth 1 row) 3.14)) 0.001))
        (should (equal (nth 2 row) "hello"))))))

;;;; Live tests — TLS (require mysql-wire-test-tls-enabled)

(defmacro mysql-wire-test--with-tls-conn (var &rest body)
  "Execute BODY with VAR bound to a TLS MySQL connection.
Skips unless both `mysql-wire-test-password' and
`mysql-wire-test-tls-enabled' are set."
  (declare (indent 1))
  `(if (or (null mysql-wire-test-password) (null mysql-wire-test-tls-enabled))
       (ert-skip "Set mysql-wire-test-password and mysql-wire-test-tls-enabled for TLS tests")
     (let ((mysql-wire-tls-verify-server nil))
       (let ((,var (mysql-wire-connect :host mysql-wire-test-host
                                  :port mysql-wire-test-port
                                  :user mysql-wire-test-user
                                  :password mysql-wire-test-password
                                  :database mysql-wire-test-database
                                  :tls t)))
         (unwind-protect
             (progn ,@body)
           (mysql-wire-disconnect ,var))))))

(ert-deftest mysql-wire-test-live-tls-connect ()
  :tags '(:mysql-wire-live :mysql-wire-tls)
  "Test TLS connection and verify encryption is active."
  (mysql-wire-test--with-tls-conn conn
    (should (mysql-wire-conn-tls conn))
    (let* ((result (mysql-wire-query conn "SHOW STATUS LIKE 'Ssl_cipher'"))
           (cipher (cadr (car (mysql-wire-result-rows result)))))
      (should (stringp cipher))
      (should (not (string-empty-p cipher))))))

(ert-deftest mysql-wire-test-live-tls-query ()
  :tags '(:mysql-wire-live :mysql-wire-tls)
  "Test query execution over TLS."
  (mysql-wire-test--with-tls-conn conn
    (let ((result (mysql-wire-query conn "SELECT 42 AS v, 'tls-ok' AS msg")))
      (let ((row (car (mysql-wire-result-rows result))))
        (should (= (car row) 42))
        (should (equal (cadr row) "tls-ok"))))))

(ert-deftest mysql-wire-test-live-tls-prepared-statement ()
  :tags '(:mysql-wire-live :mysql-wire-tls)
  "Test prepared statements over TLS."
  (mysql-wire-test--with-tls-conn conn
    (let ((stmt (mysql-wire-prepare conn "SELECT ? + 1 AS v")))
      (let ((result (mysql-wire-execute stmt 99)))
        (should (= (car (car (mysql-wire-result-rows result))) 100)))
      (mysql-wire-stmt-close stmt))))

(ert-deftest mysql-wire-test-live-tls-caching-sha2-full-auth ()
  :tags '(:mysql-wire-live :mysql-wire-tls)
  "Test caching_sha2_password full auth over TLS (auth switch path)."
  (if (or (null mysql-wire-test-password) (null mysql-wire-test-tls-enabled))
      (ert-skip "Set mysql-wire-test-password and mysql-wire-test-tls-enabled for TLS tests")
    (let ((mysql-wire-tls-verify-server nil))
      ;; Create a caching_sha2_password user and flush to force full auth
      (let ((admin (mysql-wire-connect :host mysql-wire-test-host
                                  :port mysql-wire-test-port
                                  :user mysql-wire-test-user
                                  :password mysql-wire-test-password
                                  :database mysql-wire-test-database
                                  :tls t)))
        (unwind-protect
            (progn
              (condition-case nil
                  (mysql-wire-query admin "DROP USER '_mysql_el_sha2test'@'%'")
                (mysql-wire-query-error nil))
              (condition-case err
                  (mysql-wire-query admin
                    "CREATE USER '_mysql_el_sha2test'@'%' IDENTIFIED WITH caching_sha2_password BY 'testpw'")
                (mysql-wire-query-error
                 (ert-skip (format "Server does not support caching_sha2_password: %s"
                                   (cadr err)))))
              (mysql-wire-query admin "GRANT ALL ON *.* TO '_mysql_el_sha2test'@'%'")
              (mysql-wire-query admin "FLUSH PRIVILEGES"))
          (mysql-wire-disconnect admin)))
      ;; Connect as the new user over TLS (full auth required)
      (let ((conn (mysql-wire-connect :host mysql-wire-test-host
                                 :port mysql-wire-test-port
                                 :user "_mysql_el_sha2test"
                                 :password "testpw"
                                 :database mysql-wire-test-database
                                 :tls t)))
        (unwind-protect
            (progn
              (should (mysql-wire-conn-tls conn))
              (let ((result (mysql-wire-query conn "SELECT CURRENT_USER()")))
                (should (string-prefix-p "_mysql_el_sha2test"
                                         (car (car (mysql-wire-result-rows result)))))))
          (mysql-wire-disconnect conn)))
      ;; Cleanup
      (let ((admin (mysql-wire-connect :host mysql-wire-test-host
                                  :port mysql-wire-test-port
                                  :user mysql-wire-test-user
                                  :password mysql-wire-test-password
                                  :database mysql-wire-test-database
                                  :tls t)))
        (unwind-protect
            (condition-case nil
                (mysql-wire-query admin "DROP USER '_mysql_el_sha2test'@'%'")
              (mysql-wire-query-error nil))
          (mysql-wire-disconnect admin))))))

(provide 'mysql-wire-test)
;;; mysql-wire-test.el ends here
