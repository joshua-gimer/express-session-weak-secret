# Express Session Cracker

> A Burp Suite extension and standalone tool for auditing Express.js session cookie security — detect weak secrets, crack signatures, and forge valid sessions.

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Java](https://img.shields.io/badge/Java-11+-blue)
![Python](https://img.shields.io/badge/Python-2.7%20%7C%203.x-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## Overview

Express.js applications using `express-session` sign cookies with HMAC-SHA256. If the secret is weak or a known default, attackers can:

1. **Crack the secret** via dictionary attack
2. **Forge arbitrary sessions** to impersonate users or escalate privileges
3. **Bypass authentication** entirely

This toolkit helps security professionals identify and demonstrate these vulnerabilities.

## Features

| Feature | Burp Extension | CLI Tool |
|---------|:--------------:|:--------:|
| Passive cookie capture | ✅ | — |
| Wordlist-based cracking | ✅ | ✅ |
| 70+ common secrets quick check | ✅ | — |
| Cookie forger | ✅ | — |
| Session data decoder | ✅ | — |
| Security flag analysis | ✅ | — |
| Context menu integration | ✅ | — |
| Export results | ✅ | — |

## Installation

### Burp Extension (Recommended)

**Java version** — Faster cracking (~500K-1M attempts/sec)

```bash
cd java
mvn clean package
# Load java/target/express-session-cracker.jar in Burp
```

**Python version** — No build required, needs Jython

```
1. Configure Jython in Burp: Extender → Options → Python Environment
2. Load express-session-weak-secret.py via Extender → Add
```

### Standalone CLI

```bash
# Crack a cookie with a wordlist
./crack-connect-sid.py --cookie "s%3Aabc123.xyz789..." --wordlist rockyou.txt
```

## Usage

### Burp Extension

1. **Passive Capture** — Browse target sites; cookies are captured automatically
2. **Context Menu** — Right-click requests in Proxy/Repeater → "Send cookie to Express Cracker"
3. **Manual Input** — Paste cookies from browser DevTools
4. **Quick Check** — Instantly test against 70+ common/default secrets
5. **Wordlist Attack** — Full dictionary attack with speed stats
6. **Forge Cookies** — Generate valid signed cookies with discovered secrets

### CLI Tool

```bash
# Basic usage
./crack-connect-sid.py --cookie "s%3A<sid>.<sig>" --wordlist /path/to/wordlist.txt

# With options
./crack-connect-sid.py \
  --cookie "connect.sid=s%3Aabc123.ABCDEF..." \
  --wordlist rockyou.txt \
  --ignore-empty \
  --max 1000000
```

## Technical Background

### Cookie Format

Express.js signed session cookies follow this structure:

```
s:{session_id}.{base64_signature}
```

URL-encoded in the `connect.sid` cookie:

```
connect.sid=s%3A{session_id}.{base64_signature}
```

### Signature Algorithm

```
signature = Base64( HMAC-SHA256( session_id, secret ) )
```

The signature uses standard Base64 encoding without padding (`=` characters stripped).

### Attack Vector

If an attacker recovers the secret, they can:

1. Sign arbitrary session IDs
2. Modify session data (if stored client-side)
3. Create sessions for any user
4. Bypass session fixation protections

## Common Weak Secrets

The extension includes 70+ secrets commonly found in the wild:

```
keyboard cat          # Express.js documentation example
secret                # Generic default  
my secret             # Tutorial examples
changeme              # Placeholder that stays in production
SESSION_SECRET        # Env var name used as value
your-secret-key       # Template/boilerplate leftovers
```

## Performance

| Implementation | Cracking Speed |
|----------------|----------------|
| Python (CLI)   | ~50-100K/sec   |
| Jython (Burp)  | ~50-100K/sec   |
| **Java (Burp)**| **~500K-1M/sec** |

With a 14M wordlist like `rockyou.txt`:
- Python: ~3-5 minutes
- Java: ~15-30 seconds

## Security Flags

The extension also audits cookie security attributes:

| Flag | Risk if Missing |
|------|-----------------|
| `HttpOnly` | XSS can steal session cookies |
| `Secure` | Cookies sent over HTTP (MITM) |
| `SameSite` | CSRF attacks possible |

## Project Structure

```
express-session-weak-secret/
├── README.md                    # This file
├── crack-connect-sid.py         # Standalone CLI cracker (Python 3)
├── express-session-weak-secret.py  # Burp extension (Jython/Python 2.7)
└── java/                        # High-performance Java implementation
    ├── pom.xml
    ├── README.md
    └── src/main/java/burp/
        ├── BurpExtender.java
        ├── CookieUtils.java
        ├── CommonSecrets.java
        └── ExpressCrackerTab.java
```

## Building from Source

### Java Extension

Requires: Java 11+, Maven 3.6+

```bash
cd java
mvn clean package
# Output: target/express-session-cracker.jar
```

### Python

No build required. For the Burp extension, ensure Jython standalone JAR is configured.

## Example Workflow

1. **Discover** — Browse app, extension captures `connect.sid` cookies
2. **Quick Check** — Click "Quick Check Only" to test common secrets (~instant)
3. **Deep Scan** — If not found, run full wordlist attack
4. **Verify** — Use Cookie Forger to create a test session
5. **Exploit** — Demonstrate impact by forging admin sessions
6. **Report** — Export findings as JSON for documentation

## Remediation

If you discover a weak session secret:

```javascript
// ❌ Bad
app.use(session({
  secret: 'keyboard cat'  // Default from docs!
}));

// ✅ Good
app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  }
}));
```

**Recommendations:**
- Use cryptographically random secrets (32+ bytes)
- Store secrets in environment variables, never in code
- Rotate secrets periodically
- Enable all security flags on cookies

## License

MIT License — See [LICENSE](LICENSE) for details.

## Security Notes

### Thread Safety

The Burp extension uses thread locks to prevent race conditions when:
- Capturing cookies from multiple requests
- Updating the UI during cracking

### Python 2/3 Compatibility

| Component | Python Version |
|-----------|---------------|
| Burp Extension (`express-session-weak-secret.py`) | Python 2.7 (Jython) |
| CLI Tool (`crack-connect-sid.py`) | Python 3.x |

The Burp extension uses Python 2 syntax for Jython compatibility.

### Wordlist Security

When using custom wordlists:
- Paths are not validated (runs locally, not a web service)
- Large wordlists may consume significant memory
- Consider using the Java version for large wordlists (10x faster)

### Best Practices

1. **Get Authorization** — Only test systems you have permission to test
2. **Document Findings** — Use the Export feature to create evidence
3. **Report Responsibly** — Follow responsible disclosure practices
4. **Suggest Fixes** — Include remediation guidance in reports

---

## Disclaimer

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## Contributing

Contributions welcome! Please open an issue or PR for:
- Additional common secrets
- Performance improvements
- Bug fixes
- New features

---

**Author:** Security Research  
**Burp Suite Compatibility:** Professional/Community Edition

