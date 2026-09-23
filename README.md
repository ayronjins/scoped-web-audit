# scoped-web-audit

A deliberately restricted evidence collector for web security assessments **you are authorised to perform**. It wraps `dig`, `curl`, `whatweb`, `openssl` and optionally `nmap`, and its main job is refusing to do anything outside a narrow, declared scope.

This is a defensive tool. It collects evidence about a target you control. It does not exploit anything, and it is not built to.

---

## Why it refuses so much

Security tooling is easy to point at the wrong thing. A typo in a hostname, a wildcard that expands further than you meant, a redirect that walks off-scope — and you have sent unauthorised traffic to someone else's server. That is a problem regardless of intent.

So this refuses by default and makes you state, explicitly, what you are allowed to touch:

```bash
python3 audit_web.py https://example.com \
  --authorized \
  --scope-note "own-domain self-test, ticket DEMO-1, owner Ayron Jins"
```

Both flags are mandatory. `--scope-note` is validated for content — it rejects short or meaningless strings, so you cannot satisfy it by typing `x`:

```
$ python3 audit_web.py https://example.com --authorized --scope-note "demo" --plan
error: scope note must contain a meaningful non-secret authorization reference
```

The note is written into the evidence directory. If you cannot articulate who authorised the assessment, you should not be running it.

## Everything is bounded

| Control | Value | Reason |
|---|---|---|
| Redirects | **zero**, everywhere | A redirect is how an in-scope URL becomes an out-of-scope request |
| Capture size | 256 KiB | Evidence, not a mirror of the site |
| Query strings | **rejected** | URLs with parameters routinely contain session tokens; keeping them out of evidence files prevents leaking them |
| Credentials in URL | rejected | Same reason |
| WhatWeb aggression | `1`, 1 thread, 1s wait | The lowest setting: fingerprint, do not probe |
| Timeouts | 5s connect / 20s read, per-process caps | Nothing hangs indefinitely |
| Port scan | opt-in via `--allow-host-scan` | Separate consent from the passive checks |
| Nmap scope | the target URL's **single** port | Not a range, not a sweep |

Two modes: `passive` (default — DNS, one HTTP capture, fingerprint, TLS metadata) and `safe`, which adds the single-port version probe. There is no aggressive mode. Tools that exploit rather than observe — sqlmap, wapiti, ffuf — are deliberately **not** wrapped here.

### Dry run first

`--plan` prints exactly what would be executed and sends nothing:

```
$ python3 audit_web.py https://example.com --authorized \
    --scope-note "own-domain self-test, ticket DEMO-1, owner Ayron Jins" --plan

Authorized passive assessment plan for https://example.com:
- DNS A/AAAA lookup with two-second retries
- Exact URL HTTP capture: zero redirects, 256 KiB maximum, no credentials
- WhatWeb aggression 1: one request, one thread, zero redirects
- TLS certificate handshake metadata with a 25-second process timeout
```

## Input validation

The target string reaches `subprocess` argument lists, so it is validated hard before it gets there. Hostnames go through IDNA encoding and a strict regex; anything option-like is rejected so a crafted target cannot smuggle a flag into the command line. Control characters and whitespace are rejected. Commands are built as **argument lists, never shell strings** — there is no shell to inject into.

## Output

Each run writes a timestamped directory containing the DNS answers, response headers, captured landing page, fingerprint output, TLS metadata, a `commands.json` recording exactly what ran, and the scope note. The point is an evidence trail you can hand to someone else.

`results/` is gitignored. Assessment output should not end up in version control.

## Tests

```bash
python3 -m pytest tests/ -q
# 12 passed
```

They cover the parts where a mistake has consequences: hostname validation, rejection of query strings and embedded credentials, port bounds, scope-note validation, and command construction.

## What this is not

- **Not a vulnerability scanner.** It gathers evidence; a human interprets it.
- **Not an exploitation tool.** No payloads, no injection testing, no fuzzing.
- **Not permission.** The `--authorized` flag records an assertion. It does not grant anything. Running this against infrastructure you do not own or have written permission to test is likely illegal where you live.
- **Not a replacement for the underlying tools.** `dig`, `curl`, `whatweb`, `openssl` and `nmap` must be installed separately; this constrains how they are invoked.

## Requirements

Python 3.11+ and whichever external tools your chosen mode needs. `FINDING_TEMPLATE.md` is included for writing findings up consistently.

## License

MIT — see [LICENSE](LICENSE).
