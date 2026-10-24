# Security Advisory: Untrusted X-Forwarded-Host Causes External Resource URL Injection in Pico CMS

> **Identifier:** Pending CVE assignment
> **Publication Date:** 09/10/2026
> **Last Updated:** 19/10/2026
> **Severity:** Medium (conditional impact)
> **CVSS:** 5.9 · `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N`
> **CWE:** CWE-346 (Origin Validation Error)
> **Status:** No vendor fix identified in the evaluated versions
> **Affected Component:** `Pico::getBaseUrl()` with automatic `base_url` detection

---

## 1. Executive Summary

When `base_url` is left in its default automatic mode (`base_url: ~`), Pico CMS accepts `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port` without verifying that the request came from a trusted proxy. The supplied values are used to construct absolute canonical, stylesheet, image, and JavaScript URLs in the HTML response.

This directly and reproducibly allows **external resource URL injection** in the response to an attacker-controlled request. If a shared cache stores that response without varying its cache key on the forwarded headers, later visitors can receive the injected URLs. Their browsers can then load attacker-controlled JavaScript. Thus, **web cache poisoning and cross-site scripting are conditional downstream impacts**, not effects established by the header injection alone.

The authorized lab confirmed:

- arbitrary control of absolute resource hosts through `X-Forwarded-Host`;
- generation of attacker-controlled `<script src>` URLs;
- browser execution of JavaScript served from the injected host; and
- an early return in `getBaseUrl()` that bypasses forwarded-header processing when an explicit `base_url` is configured.

The supplied lab does not contain a shared caching proxy. Consequently, the evidence does not claim that every Pico deployment is vulnerable to cache poisoning or that a direct request alone affects another user.

---

## 2. Evaluated Products

| Product | Evaluated version | Result |
|---|---:|---|
| Pico CMS | 2.1.4 | Resource URL injection confirmed |
| Pico CMS | 3.0.0-alpha.2 | Resource URL injection confirmed |
| `lib/Pico.php::getBaseUrl()` | Commits present in the lab | Trusts forwarded headers without proxy authentication |

Other releases were not dynamically evaluated and are not claimed as affected solely by version range inference.

### Configuration scope

Affected deployments use automatic base URL detection and permit untrusted clients to supply forwarded headers. An explicit, correct `base_url` prevents this code path from using those headers.

---

## 3. Root Cause

`getBaseUrl()` prefers `HTTP_X_FORWARDED_HOST` over `HTTP_HOST` without checking `REMOTE_ADDR` against a trusted-proxy list:

```php
$baseUrl = $this->getConfig('base_url');
if ($baseUrl) {
    return $baseUrl;
}

$host = 'localhost';
if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'];
} elseif (!empty($_SERVER['HTTP_HOST'])) {
    $host = $_SERVER['HTTP_HOST'];
}
```

The same method also accepts forwarded protocol and port values. The resulting URL is exposed to themes through values such as `base_url`, `theme_url`, and page URLs:

```html
<link rel="stylesheet" href="http://attacker.example/themes/default/css/style.css" />
<script src="http://attacker.example/themes/default/js/pico.js"></script>
```

This is a trust-boundary failure: headers intended to be asserted by infrastructure are accepted from any requester.

---

## 4. Security Impact

### Directly established impact

An unauthenticated requester can cause Pico to generate a response containing attacker-selected hosts in absolute resource and canonical URLs. Without an intermediary that reuses this response, the altered response is normally returned only to the requester who supplied the header.

### Conditional cache poisoning and XSS impact

Impact on other visitors requires all of the following:

1. `base_url` is unset or null;
2. untrusted clients can supply `X-Forwarded-*` headers to Pico;
3. a shared intermediary caches the generated HTML;
4. the intermediary's cache key does not distinguish the relevant forwarded headers;
5. a victim later receives the cached response and loads its external resources; and
6. browser policy, including Content Security Policy and mixed-content rules, permits the resource.

When these conditions hold, attacker-hosted JavaScript referenced by the cached page executes in the document's origin and can alter the page, make same-origin requests, and access browser-visible data available to that origin.

---

## 5. Severity

### CVSS v3.1

- **Score:** 5.9 (Medium)
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N`

| Metric | Value | Rationale |
|---|---|---|
| AV | Network | The header is supplied remotely |
| AC | High | Victim impact depends on a shared cache and cache-key behavior |
| PR | None | No Pico account is required |
| UI | Required | A victim must load an affected cached page |
| S | Unchanged | Execution occurs in the affected site's browser origin |
| C | Low | Conditional access to browser-visible information |
| I | High | Conditional script execution can modify content and issue actions |
| A | None | No availability impact was established |

The header-controlled URL generation alone has less impact than this conditional chain. The score above represents the demonstrated primitive combined with the explicitly stated cache preconditions.

### CWE

- **CWE-346: Origin Validation Error** — Pico accepts proxy-originated metadata without establishing that its source is a trusted proxy.

The issue does not require conflicting HTTP parsers or dynamic language evaluation; it is classified around the missing validation of proxy-originated metadata.

---

## 6. Proof of Concept

### Header injection

```bash
curl -H 'X-Forwarded-Host: 127.0.0.1:8888' \
     -H 'X-Forwarded-Proto: http' \
     http://127.0.0.1:9087/
```

Expected vulnerable response fragment:

```html
<script src="http://127.0.0.1:8888/themes/default/js/pico.js"></script>
```

The included `poc.sh` starts from this primitive and renders the altered response in a browser while a controlled server supplies JavaScript. This verifies that the injected resource URL can lead to JavaScript execution.

### What the PoC does not prove

- It does not include or compromise a production CDN or reverse proxy.
- It does not prove that a particular cache ignores `X-Forwarded-Host` in its key.
- It does not show a direct request altering the response of an unrelated visitor.
- Cache poisoning must be tested separately against the actual authorized deployment.

---

## 7. Lab Evidence

The authorized lab observed three absolute script URLs rewritten to the supplied host. Chromium then loaded JavaScript from the controlled host and inserted the expected marker into the DOM.

Available evidence:

- `evidence/vulnerability-exposure.png`
- `evidence/poc-execution.png`
- `evidence/02_xss_live_reproduzido.png`
- `evidence/03_cadeia_causa_efeito.png`
- `evidence/04_poc_execution_live.png`
- `evidence/05_poc_live_execution_20261015.png`
- `evidence/poisoned_response.html`
- `evidence/poisoned_headers.txt`

These artifacts demonstrate URL injection and browser resource execution. They do not independently demonstrate reuse by a shared cache.

---

## 8. Remediation

### Deployment mitigation

Set an explicit canonical URL:

```yaml
base_url: https://www.example.com/
```

At the edge proxy, discard client-provided forwarded headers and set canonical values. Reject unexpected `Host` values. Do not allow direct public access to the backend that trusts proxy metadata.

Add a restrictive Content Security Policy as defense in depth:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'
```

### Recommended vendor fix

1. Ignore all `X-Forwarded-*` headers by default.
2. Add an explicit `trusted_proxies` configuration.
3. Use forwarded headers only when `REMOTE_ADDR` matches a trusted proxy.
4. Validate the resulting host against a configured allowlist.
5. Reject invalid or unexpected hosts rather than silently reflecting them.
6. Document that an explicit `base_url` is the safest production configuration.

Cache variation headers alone are not a complete fix. Sanitizing the input at the trust boundary is preferred.

---

## 9. Detection

Monitor for:

- forwarded-host values outside the deployment's domain allowlist;
- cached HTML containing resource URLs for unrelated domains;
- cache hits serving different embedded hosts for the same canonical page; and
- outbound browser requests to unexpected stylesheet or script origins.

---

## 10. Disclosure Timeline

| Date | Event |
|---|---|
| 09/10/2026 | Header trust issue identified and tested in the authorized lab |
| 09/10/2026 | External JavaScript resource execution reproduced |
| 19/10/2026 | Finding reframed as resource URL injection with conditional cache poisoning/XSS impact |
| Pending | Vendor notification |
| Pending | Vendor assessment and coordinated remediation |

---

## 11. References

- CWE-346: https://cwe.mitre.org/data/definitions/346.html
- Pico CMS: https://github.com/picocms/Pico
- CVSS v3.1: https://www.first.org/cvss/calculator/3.1

---

## 12. Legal Notice

Testing was performed only in an authorized local lab. The PoC is intended for defensive validation and coordinated disclosure.
