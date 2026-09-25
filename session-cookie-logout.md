# Security Advisory — Session cookie without security flags + improper logout

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-24**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`
> **CWE:** CWE-1004: Sensitive Cookie Without HttpOnly, CWE-1275: Sensitive Cookie with Improper SameSite, CWE-614: Sensitive Cookie Without Secure, CWE-613: Insufficient Session Expiration
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **(global session configuration), logoutadmin.php, logoutfaculty.php, logoutstudent.php**, that allows **an attacker (None; user interaction: Required (chaining with XSS/CSRF))** to exploit a **Session Management Weaknesses** flaw.

Session cookie is issued without `HttpOnly`/`SameSite`/`Secure` (amplifies XSS and CSRF). Logout contains `==` bug (comparison vs assignment) and never calls `session_destroy()`/`session_regenerate_id()`; ID remains valid after 'logout'.

Successful exploitation may result in **Session theft via XSS (HttpOnly absent); CSRF facilitation (SameSite absent); sessions not terminated.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: (global session configuration), logoutadmin.php, logoutfaculty.php, logoutstudent.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Session Management Weaknesses** in the component **(global session configuration)**.

Session cookie is issued without `HttpOnly`/`SameSite`/`Secure` (amplifies XSS and CSRF). Logout contains `==` bug (comparison vs assignment) and never calls `session_destroy()`/`session_regenerate_id()`; ID remains valid after 'logout'.

**Root cause (source code snippet):**

**`logoutadmin.php`**

```php
session_start();
$_SESSION["umail"]=="";   // BUG: '==' is comparison; zeros nothing
session_unset('umail');    // session_unset() ignores arguments
header('Location:index.php'); // no session_destroy(); ID preserved
```

### Necessary Conditions

- Authentication: None
- User Interaction: Required (chaining with XSS/CSRF)
- Attack Vector: Remote (network) — method GET/POST
- Preconditions: Amplifier — impact materializes chained with XSS (item 03+) and CSRF (item 23).

---

## 4. Impact

Exploitation may allow:

- Session theft via XSS (HttpOnly absent)
- CSRF facilitation (SameSite absent)
- sessions not terminated

### Impact on Confidentiality

Low — partial/limited information exposure.

### Impact on Integrity

Low — limited data/state modification.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 5.4
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

### CWE

- CWE-1004: Sensitive Cookie Without HttpOnly
- CWE-1275: Sensitive Cookie with Improper SameSite
- CWE-614: Sensitive Cookie Without Secure
- CWE-613: Insufficient Session Expiration

### CAPEC

- **CAPEC-31 – Accessing/Intercepting/Modifying HTTP Cookies**
- **CAPEC-62 – Cross Site Request Forgery**
- **CAPEC-102 – Session Sidejacking**
- **CAPEC-60 – Reusing Session IDs**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Request page with `session_start()` (e.g., welcomeadmin.php) and inspect `Set-Cookie` header.
2. Confirm absence of `HttpOnly`, `SameSite`, `Secure`.
3. Steal cookie via stored XSS (`document.cookie`) — possible due to missing HttpOnly.
4. Confirm logout does not invalidate session (no `session_destroy`).

---

## 7. Technical Evidence

### Affected Component

```text
File(s): (global session configuration), logoutadmin.php, logoutfaculty.php, logoutstudent.php
Parameter(s): PHPSESSID (cookie)
Method: GET/POST · Authentication: None
```

### Example Request

```http
POST /(global session configuration) HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

<form fields>
```

### Observed Response

```text
Set-Cookie: PHPSESSID=...; path=/  → HttpOnly ABSENT, SameSite ABSENT, Secure ABSENT.
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Session Management Weaknesses flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

![Web execution evidence — 24-session-cookie-logout](evidencia-web-24-session-cookie-logout.png)

**b) Vulnerable code line** (`(global session configuration)`):

![Source code evidence — 24-session-cookie-logout](evidencia-codigo-24-session-cookie-logout.png)

> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -i http://192.168.95.131:9292/welcomeadmin.php | grep -i "set-cookie"
# -> Set-Cookie: PHPSESSID=...; path=/   (no HttpOnly/SameSite/Secure)
```

### Expected Result

```text
Set-Cookie: PHPSESSID=...; path=/  → HttpOnly ABSENT, SameSite ABSENT, Secure ABSENT.
```


### PoC Limitations

- Does not cause intentional unavailability.
- Does not remove or modify third-party data (state injections are restored; error-based aborts before persisting).
- Does not create persistence or backdoor.
- Does not contain real credentials (lab test data only).
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Access an instance of **CloudClassroom-PHP-Project 1.0**.
2. Configure the prerequisite: Amplifier — impact materializes chained with XSS (item 03+) and CSRF (item 23).
3. Access the component **(global session configuration)** (parameter(s): PHPSESSID (cookie)).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: Set-Cookie: PHPSESSID=...; path=/  → HttpOnly ABSENT, SameSite ABSENT, Secure ABSENT.
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- `session_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Strict'])` before `session_start()`.
- `session_regenerate_id(true)` on login; on logout: `$_SESSION=[]; session_unset(); session_destroy();`

Additional compensatory measures:

- Restrict access to affected component (network/ACL/WAF).
- Apply WAF/reverse proxy rules to block known attack patterns.
- Review associated permissions and privileges; invalidate potentially exposed sessions/credentials.
- Maintain logs and evidence for investigation.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of this advisory date (unpatched product).**

When made available, recommended:

1. Update to patched version or later.
2. Restart affected services, if necessary.
3. Invalidate old sessions and credentials.
4. Review logs prior to update.
5. Confirm vulnerable behavior can no longer be reproduced.

### Recommended Change to Vendor

- `session_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Strict'])` before `session_start()`.
- `session_regenerate_id(true)` on login; on logout: `$_SESSION=[]; session_unset(); session_destroy();`

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Reuse of same `PHPSESSID` before and after authentication; session cookies without `HttpOnly`/`SameSite`/`Secure`.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "(global session configuration)"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 02/08/2026 | Vulnerability identified (static analysis) |
| 02/08/2026 | Confirmed dynamically in authorized lab |
| 02/08/2026 | Re-validated live with evidence (browser + code) |
| 02/08/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notification |
| (pending) | CVE requested/reserved |
| (pending) | Fix made available |
| (pending) | Advisory publication |

---

## 14. Vendor Communication

- **Vendor:** Vishal Mathur (`mathurvishal`)
- **Channel used:** Private GitHub Security Advisory of repository / maintainer email (see `VENDOR-EMAIL.md`)
- **Date of first notification:** (pending)
- **Response status:** Awaiting notification/response
- **Vendor positioning:** N/A at this time

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** vinniboy021@gmail.com
- **Organization:** Independent security research
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/
- https://github.com/mathurvishal/CloudClassroom-PHP-Project
- https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 02/08/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive and security improvement purposes.

Information presented was obtained in authorized environment and disclosed responsibly or coordinately. The author does not encourage use of this information for unauthorized access, service interruption, privacy violation or any illegal activity.

Use of information in this document is solely the reader's responsibility.

---

## 19. Contact

For corrections, updates or additional information:

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
