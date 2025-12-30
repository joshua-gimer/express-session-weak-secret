# Express Session Cracker - Burp Suite Extension

A high-performance Burp Suite extension for detecting, cracking, and forging Express.js `connect.sid` session cookies.

## Features

- **Passive Cookie Capture** - Automatically captures `connect.sid` cookies from HTTP traffic
- **Wordlist Cracking** - HMAC-SHA256 brute-force with speed stats (500K+ attempts/sec)
- **Common Secrets Quick Check** - 70+ built-in default/weak secrets
- **Cookie Forger** - Create valid signed cookies with known secrets
- **Session Decoder** - Decode and analyze session data (base64, JSON, etc.)
- **Context Menu** - Right-click to send cookies from Proxy/Repeater
- **Export** - Save cookies as JSON, export discovered secrets

## Building

### Prerequisites

- Java 11 or higher
- Maven 3.6 or higher

### Build Commands

```bash
cd java

# Build the extension JAR
mvn clean package

# The JAR will be created at:
# target/express-session-cracker.jar
```

### One-liner

```bash
mvn clean package -f java/pom.xml
```

## Installation in Burp Suite

1. Build the JAR (see above)
2. Open Burp Suite
3. Go to **Extender** → **Extensions** → **Add**
4. Extension Type: **Java**
5. Select the JAR file: `target/express-session-cracker.jar`
6. Click **Next** to load

## Usage

### Tab: Capture & Crack

1. **Automatic Capture**: Browse target sites - cookies are captured automatically
2. **Manual Add**: Click "Add Cookie Manually" to paste a cookie
3. **Context Menu**: Right-click requests in Proxy/Repeater → "Send cookie to Express Cracker"
4. **Configure Wordlist**: Browse to select a wordlist file (e.g., `rockyou.txt`)
5. **Quick Check**: Try common secrets first (checkbox enabled by default)
6. **Crack**: Select cookies and click "Crack Selected" or "Crack All"

### Tab: Cookie Forger

Once you've cracked a secret:

1. Click "Use Discovered" to populate the secret field
2. Enter or generate a Session ID
3. Click "Generate Signed Cookie"
4. Copy the result (raw, URL-encoded, or full header)

### Tab: Session Decoder

- Paste any `connect.sid` cookie to decode the session data
- Double-click cookies in the table to auto-decode

### Tab: Settings & Export

- Export captured cookies as JSON
- Export discovered secrets as text
- View the built-in common secrets list

## Performance

Java implementation provides significantly faster cracking than Python/Jython:

| Implementation | Speed (approx.) |
|----------------|-----------------|
| Python/Jython  | 50-100K/sec     |
| **Java**       | **500K-1M/sec** |

## Common Secrets Included

The extension includes 70+ common secrets:
- Express defaults: `"keyboard cat"`, `"secret"`
- Tutorial examples: `"my secret"`, `"your-secret-key"`
- Environment patterns: `SESSION_SECRET`, `APP_SECRET`
- Common passwords: `password`, `admin`, `changeme`

## Technical Details

### Cookie Format

Express.js signed cookies use the format:
```
s:{session_id}.{base64_hmac_sha256_signature}
```

The signature is computed as:
```
HMAC-SHA256(session_id, secret) → base64 (no padding)
```

### Security Flags Checked

The extension logs warnings for cookies missing:
- `HttpOnly` - Prevents JavaScript access
- `Secure` - HTTPS-only transmission
- `SameSite` - CSRF protection

## License

MIT License

