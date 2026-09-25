# Security Advisory — Broken Access Control via redirect without exit (Execution After Redirect)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-00**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Critical
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
> **CWE:** CWE-862: Missing Authorization, CWE-698: Execution After Redirect (EAR)
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **managevideos2.php, updatefaculty.php, updateguest.php, updatequery.php, updatestudent.php, (pattern present throughout the application)**, that allows **an attacker (None; user interaction: None)** to exploit a **Broken Access Control / Missing Authorization** flaw.

All restricted pages check the session with `header('Location:...')` but do NOT call `exit`/`die`. PHP merely schedules the redirect header and continues executing, emitting the protected body (HTTP 302 with full body). Clients that do not follow redirects (curl, Burp, scripts) receive the data and trigger queries — without session.

Successful exploitation may result in **Exposure of all admin/faculty screens (CRUD of students, teachers, queries, videos, guests) to anonymous users; enables unauthenticated read/write via SQLi.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: managevideos2.php, updatefaculty.php, updateguest.php, updatequery.php, updatestudent.php, (pattern present throughout the application) | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Broken Access Control / Missing Authorization** in the component **managevideos2.php**.

All restricted pages check the session with `header('Location:...')` but do NOT call `exit`/`die`. PHP merely schedules the redirect header and continues executing, emitting the protected body (HTTP 302 with full body). Clients that do not follow redirects (curl, Burp, scripts) receive the data and trigger queries — without session.

**Root cause (source code snippet):**

**`updatestudent.php:4-7`**

```php
if ( $_SESSION["umail"]=="" || $_SESSION["umail"]==NULL ) {
    header('Location:AdminLogin.php');
}   // <-- no exit; execution continues
$userid = $_SESSION["umail"];
```

### Necessary Conditions

- Authentication: None
- User Interaction: None
- Attack Vector: Remote (network) — method GET/POST
- Preconditions: None. It is the systemic defect that makes 'authenticated' SQLi of other items unauthenticated.

---

## 4. Impact

Exploitation may allow:

- Exposure of all admin/faculty screens (CRUD of students, teachers, queries, videos, guests) to anonymous users
- enables unauthenticated read/write via SQLi

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 9.1
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

### CWE

- CWE-862: Missing Authorization
- CWE-698: Execution After Redirect (EAR)

### CAPEC

- **CAPEC-1 – Accessing Functionality Not Properly Constrained by ACLs**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Choose a restricted page (e.g., `updatestudent.php`).
2. Send the request WITHOUT session cookie and WITHOUT following redirects (`curl` without `-L`).
3. Observe HTTP 302 but with full body (Content-Length > 4 KB) containing restricted form/data.
4. Conclude that the guard does not prevent access; sensitive logic executes anyway.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): managevideos2.php, updatefaculty.php, updateguest.php, updatequery.php, updatestudent.php, (pattern present throughout the application)
Parameter(s): —
Method: GET/POST · Authentication: None
```

### Example Request

```http
POST /managevideos2.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

<form fields>
```

### Observed Response

```text
managevideos2.php?editassid=1 -> HTTP=302 SIZE=5118 (restricted body rendered)
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Broken Access Control / Missing Authorization flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

![Web execution evidence — 00-broken-access-control](evidencia-web-00-broken-access-control.png)

**b) Vulnerable code line** (`managevideos2.php`):

![Source code evidence — 00-broken-access-control](evidencia-codigo-00-broken-access-control.png)

> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -i "http://192.168.95.131:9292/updatestudent.php?eno=146891650" | head -1
# -> HTTP/1.1 302 Found  (but body contains FName, Address, Phone, Email and PASSWORD of student)
```

### Expected Result

```text
managevideos2.php?editassid=1 -> HTTP=302 SIZE=5118 (restricted body rendered)
updatestudent.php?eno=146891650 -> HTTP=302 SIZE=5031 (marker 'Enrolment' present)
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
2. Configure the prerequisite: None. It is the systemic defect that makes 'authenticated' SQLi of other items unauthenticated.
3. Access the component **managevideos2.php** (parameter(s): —).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: managevideos2.php?editassid=1 -> HTTP=302 SIZE=5118 (restricted body rendered)
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Apply `exit;` immediately after every `header('Location:...')` authorization.
- Centralize verification in a guard included at top (e.g., `auth_guard.php`).
- Affirmative role verification per page (see item 25).

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

- Apply `exit;` immediately after every `header('Location:...')` authorization.
- Centralize verification in a guard included at top (e.g., `auth_guard.php`).
- Affirmative role verification per page (see item 25).

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Access to `managevideos2.php` without valid session (HTTP 302 responses accompanied by full body) or by wrong role/privilege.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "managevideos2.php"
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
