# Security Advisory: Origin Validation Error in development/test CORS configuration

> **Identifier:** JM-CORS-02 / Pending CVE assignment
> **Publication Date:** 09/10/2026
> **Last Updated:** 09/10/2026
> **Severity:** High
> **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
> **CWE:** CWE-346: Origin Validation Error
> **Status:** Unpatched

---

## 1. Executive Summary

In development and test modes, Jekyll Manager 0.1.1 reflects an arbitrary Origin and permits DELETE, GET, OPTIONS, POST and PUT. A web origin can therefore issue mutation requests to a reachable API. The lab confirmed the preflight response and an HTTP 200 cross-origin-style PUT.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-manager | 0.1.1 (`fd4a9a43a501ff6511795a201ecb42100b82af71`) | None known | Affected/under review |
| Component: development/test CORS configuration | 0.1.1 | None known | Unpatched |

- **Repository / Ecosystem:** https://github.com/jekyll/jekyll-admin / RubyGems
- **Evaluated stack:** Ruby 2.7.8, Jekyll 4.4.1, Sinatra 1.4.8, WEBrick 1.9.2, Docker/Linux

### Unaffected Products

- None evaluated.

---

## 3. Vulnerability Description

Sinatra::CrossOrigin is enabled without an origin allow-list while mutating methods are allowed. The evaluated API also lacks authentication, increasing the impact of browser-originated requests.

**Root cause:**

```ruby
enable :cross_origin
disable :allow_credentials
set :allow_methods, [:delete, :get, :options, :post, :put]
```

### Necessary Conditions

- **Authentication:** None in evaluated deployment
- **User interaction:** Victim browser must be able to reach the target
- **Attack vector:** Network
- **Preconditions:** The service runs in development/test mode and is reachable from the browser running attacker-controlled JavaScript.

---

## 4. Impact

Cross-origin creation, modification, or deletion through exposed API routes.

- **Confidentiality:** None demonstrated
- **Integrity:** High: API-backed files can be modified
- **Availability:** None directly demonstrated

---

## 5. Classification

### CVSS

- **Score:** 7.5
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | None |
| Integrity (I) | High |
| Availability (A) | None |

### CWE

- CWE-346: Origin Validation Error

### CAPEC (optional)

- N/A

---

## 6. Exploitation Scenario

1. Start the authorized lab in development mode.
2. Send an OPTIONS preflight with an arbitrary Origin and requested method PUT.
3. Observe the Origin reflected and PUT listed in allowed methods.
4. Send the test PUT with the same Origin.
5. Confirm the API returns HTTP 200 and the file exists.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): `lib/jekyll-admin/server.rb` lines 19-24 and 31-35
Parameter(s): HTTP `Origin` and `Access-Control-Request-Method` headers
Method: HTTP · Authentication: None in evaluated deployment
```

### Example Request

```http
OPTIONS /_api/static_files HTTP/1.1
Host: 127.0.0.1:4000
Origin: http://attacker.com
Access-Control-Request-Method: PUT
```

### Observed Response

```text
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Methods: DELETE, GET, OPTIONS, POST, PUT

Subsequent PUT /_api/static_files/cors_test.txt returned HTTP 200.
```

### Result

Reproduced in the authorized local Docker lab on 09/10/2026. The test was bounded and used synthetic data only. Cross-origin creation, modification, or deletion through exposed API routes.

**Evidence:** 
<img width="1598" height="668" alt="poc-execution" src="https://github.com/user-attachments/assets/b63dab86-d552-439f-b8d4-38fcd72c33aa" />

---

## 8. Proof of Concept

This PoC is intended only for authorized environments and demonstrates the observed behavior with bounded test data.

[poc.sh](https://github.com/user-attachments/files/33358261/poc.sh)

```text
./poc.sh http://127.0.0.1:4000
```

### Expected Result

```text
The arbitrary Origin is allowed and the test file is created with HTTP 200.
```

### PoC Limitations

- The PoC uses curl to reproduce the protocol exchange. The response headers establish browser permission; no third-party system is contacted.
- Does not target third-party systems or contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Start the authorized lab in development mode.
2. Send an OPTIONS preflight with an arbitrary Origin and requested method PUT.
3. Observe the Origin reflected and PUT listed in allowed methods.
4. Send the test PUT with the same Origin.
5. Confirm the API returns HTTP 200 and the file exists.

---

## 10. Mitigation

- Disable CORS when cross-origin administration is unnecessary.
- Use an explicit allow-list of trusted HTTPS origins.
- Require authentication, authorization, and CSRF defenses on mutation routes.

> Mitigations reduce risk but may not completely eliminate the underlying behavior.

---

## 11. Fix

**No official fixed version was identified as of 09/10/2026.**

Recommended actions:

1. Apply the vendor-provided patched version when available.
2. Restart affected services if required by the update.
3. Review logs for the indicators listed below.
4. Repeat the bounded PoC to confirm the behavior is no longer reproducible.

### Recommended Change to Vendor

- Configure Sinatra::CrossOrigin with a strict origin allow-list.
- Remove mutation methods from public CORS policy and reject unapproved origins.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- OPTIONS or mutation requests to `/_api/*` carrying unexpected Origin values.

### Example Log Search

```text
OPTIONS or mutation requests to `/_api/*` carrying unexpected Origin values.
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 09/10/2026 | Finding identified through static analysis and dynamic testing |
| 09/10/2026 | Behavior confirmed in authorized local environment |
| 09/10/2026 | Disclosure package and visual evidence prepared |
| 13/10/2026 | Vendor notified |
| pending | CVE requested or reserved, if applicable |
| pending | Fix made available |
| pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** jekyll-manager maintainers
- **Channel used:** Pending private GitHub Security Advisory
- **Date of first notification:** Pending
- **Response status:** Awaiting notification
- **Vendor position:** N/A

---

## 15. Credits

- **Researcher:** vinniboy021
- **Organization:** Independent
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- https://github.com/jekyll/jekyll-admin
- https://www.first.org/cvss/calculator/3.1
- https://cwe.mitre.org/

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 09/10/2026 | Initial publication using the standard advisory template |

---

## 18. Legal Notice

This advisory is published for educational, defensive and security improvement purposes.

Information presented was obtained in authorized environment and disclosed responsibly or coordinately. The author does not encourage use of this information for unauthorized access, service interruption, privacy violation or any illegal activity.

Use of information in this document is solely the reader's responsibility.

---

## 19. Contact

For corrections, updates or additional information:

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/ashmaroli/jekyll-manager
