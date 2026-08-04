# Security Advisory — UNAUTHENTICATED Stored XSS via self-registration (registrationform.php → studentdetails.php)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-36**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Medium
> **CVSS:** 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Cross-site Scripting
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **registrationform.php, studentdetails.php**, that allows **an attacker (NONE (PUBLIC self-registration endpoint — no item 00 required); user interaction: Required (admin opens student listing))** to exploit a **Stored / Persistent Cross-Site Scripting (public self-registration)** flaw.

PUBLIC registration form (`registrationform.php`) persists fields via `INSERT INTO studenttable` without sanitization. Name is rendered WITHOUT encoding in admin listing `studentdetails.php`, so an ANONYMOUS attacker can store XSS that executes in the ADMINISTRATOR's browser — direct chain to admin account takeover (with unprotected cookie, item 24). Same INSERT is injectable via SQLi (see item 37).

Successful exploitation may result in **Critical chain: UNAUTHENTICATED attacker stores XSS that executes in ADMINISTRATOR's browser → theft of admin session cookie (item 24) → full control.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: registrationform.php, studentdetails.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Stored / Persistent Cross-Site Scripting (public self-registration)** in the component **registrationform.php**.

PUBLIC registration form (`registrationform.php`) persists fields via `INSERT INTO studenttable` without sanitization. Name is rendered WITHOUT encoding in admin listing `studentdetails.php`, so an ANONYMOUS attacker can store XSS that executes in the ADMINISTRATOR's browser — direct chain to admin account takeover (with unprotected cookie, item 24). Same INSERT is injectable via SQLi (see item 37).

**Root cause (source code snippet):**

**`registrationform.php:87`**

```php
$sql = "INSERT INTO `studenttable` (`FName`,`LName`,...,`Course`) VALUES ('$fname','$lname',...,'$course')";  // public, unsan
```

**`studentdetails.php:67`**

```php
<?PHP echo $row['FName'];?>   // self-register name rendered WITHOUT encoding in admin panel
```

### Necessary Conditions

- Authentication: NONE (PUBLIC self-registration endpoint — no item 00 required)
- User Interaction: Required (admin opens student listing)
- Attack Vector: Remote (network) — method POST
- Preconditions: None (public endpoint). Admin opens `studentdetails.php` to trigger.

---

## 4. Impact

Exploitation may allow:

- Critical chain: UNAUTHENTICATED attacker stores XSS that executes in ADMINISTRATOR's browser → theft of admin session cookie (item 24) → full control

### Impact on Confidentiality

Low — partial/limited information exposure.

### Impact on Integrity

Low — limited data/state modification.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 6.1
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Changed (C) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

### CWE

- CWE-79: Cross-site Scripting

### CAPEC

- **CAPEC-63 – Cross-Site Scripting (XSS)**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. As ANONYMOUS, send POST to `registrationform.php` with `fname` = `<svg onload=alert(1)>` (FName varchar(30): use short vector that stores/executes intact).
2. Registration created (public INSERT).
3. When admin opens `studentdetails.php`, payload executes in admin context (session theft).
4. (Non-destructive PoC) remove test record via `studentdetails.php?deleteid=<Eno>`.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): registrationform.php, studentdetails.php
Parameter(s): fname, lname, faname, addrs, course, gender, phno, email, pass
Method: POST · Authentication: NONE (PUBLIC self-registration endpoint — no item 00 required)
```

### Example Request

```http
POST /registrationform.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

fname=<value>&lname=<value>&faname=<value>&addrs=<value>&course=<value>&gender=<value>&phno=<value>&email=<value>&pass=<value>
```

### Observed Response

```text
anonymous payload reflected WITHOUT encoding in studentdetails.php (admin panel): <svg onload=alert(1)>
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Stored / Persistent Cross-Site Scripting (public self-registration) flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

![Web execution evidence — 36-registrationform-stored-xss](evidencia-web-36-registrationform-stored-xss.png)

**b) Vulnerable code line** (`registrationform.php`):

![Source code evidence — 36-registrationform-stored-xss](evidencia-codigo-36-registrationform-stored-xss.png)

> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s "http://192.168.95.131:9292/registrationform.php" \
  --data-urlencode "fname=<svg onload=alert(1)>" \
  --data-urlencode "lname=x" --data-urlencode "faname=x" --data-urlencode "dob=2000-01-01" \
  --data-urlencode "addrs=x" --data-urlencode "gender=Male" --data-urlencode "phno=1" \
  --data-urlencode "email=poc@x.com" --data-urlencode "pass=x" --data-urlencode "course=x" \
  --data-urlencode "submit=1"
# then: open studentdetails.php (admin) and remove via studentdetails.php?deleteid=<Eno>
```

### Expected Result

```text
anonymous payload reflected WITHOUT encoding in studentdetails.php (admin panel): <svg onload=alert(1)>
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
2. Configure the prerequisite: None (public endpoint). Admin opens `studentdetails.php` to trigger.
3. Access the component **registrationform.php** (parameter(s): fname, lname, faname, addrs, course, gender, phno, email, pass).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: anonymous payload reflected WITHOUT encoding in studentdetails.php (admin panel): <svg onload=alert(1)>
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Encode all dynamic output with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in correct context.
- Validate/limit input content and use Content-Security-Policy.
- Prepared statements in persistence (defense in depth).
- Prepared statements on self-registration INSERT (defense in depth; see item 37).

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

- Encode all dynamic output with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in correct context.
- Validate/limit input content and use Content-Security-Policy.
- Prepared statements in persistence (defense in depth).
- Prepared statements on self-registration INSERT (defense in depth; see item 37).

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Values persisted via `registrationform.php` containing `<script`, `onerror=`, `onload=`, `<svg` or `</textarea>`.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "registrationform.php"
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

- **Emails:** rmsbpro@gmail.com and vinniboy021@gmail.com
- **Repository:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
