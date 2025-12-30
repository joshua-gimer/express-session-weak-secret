package burp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * Utilities for parsing, signing, and cracking Express.js connect.sid cookies.
 */
public final class CookieUtils {

    private CookieUtils() {}

    /**
     * Parsed cookie containing SID and signature.
     */
    public static class ParsedCookie {
        public final String sid;
        public final String signature;

        public ParsedCookie(String sid, String signature) {
            this.sid = sid;
            this.signature = signature;
        }
    }

    /**
     * Result of a cracking attempt.
     */
    public static class CrackResult {
        public final String secret;       // null if not found
        public final long attempts;
        public final double elapsedSeconds;

        public CrackResult(String secret, long attempts, double elapsedSeconds) {
            this.secret = secret;
            this.attempts = attempts;
            this.elapsedSeconds = elapsedSeconds;
        }

        public boolean isFound() {
            return secret != null;
        }

        public double getSpeed() {
            return elapsedSeconds > 0 ? attempts / elapsedSeconds : 0;
        }
    }

    /**
     * Decoded session data.
     */
    public static class DecodedSession {
        public final String raw;
        public final String decoded;
        public final String type;      // "base64-json", "base64-string", "base64-binary", "session-store-key"
        public final String json;      // Pretty-printed JSON if applicable

        public DecodedSession(String raw, String decoded, String type, String json) {
            this.raw = raw;
            this.decoded = decoded;
            this.type = type;
            this.json = json;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Parsing
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Parse a connect.sid cookie value to extract SID and signature.
     * Accepts full "connect.sid=..." string or just the value part.
     */
    public static ParsedCookie parse(String cookieValue) throws IllegalArgumentException {
        String s = cookieValue.trim();

        // Strip cookie name if present
        if (s.contains("connect.sid=")) {
            s = s.split("connect\\.sid=", 2)[1].trim();
        }

        // Handle multiple cookies (take first)
        if (s.contains(";")) {
            s = s.split(";", 2)[0].trim();
        }

        // URL decode
        try {
            s = URLDecoder.decode(s, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            // Ignore decoding errors, continue with raw value
        }

        // Must start with "s:" for signed cookies
        if (!s.startsWith("s:")) {
            throw new IllegalArgumentException("Cookie missing 's:' prefix (not signed?)");
        }

        String body = s.substring(2);  // drop "s:"

        if (!body.contains(".")) {
            throw new IllegalArgumentException("Missing '.' separator between SID and signature");
        }

        // Signature is after the LAST dot
        int lastDot = body.lastIndexOf('.');
        String sid = body.substring(0, lastDot);
        String sig = body.substring(lastDot + 1);

        if (sid.isEmpty() || sig.isEmpty()) {
            throw new IllegalArgumentException("Empty SID or signature");
        }

        return new ParsedCookie(sid, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signing
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Compute HMAC-SHA256 signature for a SID using the given secret.
     * Returns base64 without padding (standard, not URL-safe).
     */
    public static String computeSignature(String sid, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
            );
            mac.init(keySpec);
            byte[] hmac = mac.doFinal(sid.getBytes(StandardCharsets.UTF_8));

            // Base64 encode without padding
            return Base64.getEncoder().withoutPadding().encodeToString(hmac);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    /**
     * Compute URL-safe base64 signature (used by some deployments).
     */
    public static String computeSignatureUrlSafe(String sid, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
            );
            mac.init(keySpec);
            byte[] hmac = mac.doFinal(sid.getBytes(StandardCharsets.UTF_8));

            // URL-safe Base64 encode without padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    /**
     * Check if a signature matches for the given SID and secret.
     * Checks both standard and URL-safe base64 encodings.
     */
    public static boolean signatureMatches(String sid, String targetSig, String secret) {
        String stdSig = computeSignature(sid, secret);
        if (targetSig.equals(stdSig)) {
            return true;
        }

        String urlSig = computeSignatureUrlSafe(sid, secret);
        return targetSig.equals(urlSig);
    }

    /**
     * Sign a session ID with the given secret, returning the full cookie value.
     * Format: s:{sid}.{signature}
     */
    public static String signCookie(String sid, String secret) {
        String sig = computeSignature(sid, secret);
        return "s:" + sid + "." + sig;
    }

    /**
     * URL-encode a cookie value for use in Cookie header.
     */
    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return value;
        }
    }

    /**
     * Generate a random UUID suitable for use as a session ID.
     */
    public static String generateUUID() {
        return UUID.randomUUID().toString();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cracking
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Quick check against common secrets.
     */
    public static CrackResult crackWithCommonSecrets(String sid, String targetSig) {
        long start = System.nanoTime();
        int attempts = 0;

        for (String secret : CommonSecrets.SECRETS) {
            attempts++;
            if (signatureMatches(sid, targetSig, secret)) {
                double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
                return new CrackResult(secret, attempts, elapsed);
            }
        }

        double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
        return new CrackResult(null, attempts, elapsed);
    }

    /**
     * Crack a cookie using a wordlist file.
     *
     * @param sid            The session ID
     * @param targetSig      The signature to match
     * @param wordlistPath   Path to wordlist file
     * @param progressCallback Called periodically with (attempts, currentSpeed) - can be null
     * @param cancelFlag     Set to true to cancel - can be null
     * @return CrackResult with the secret if found
     */
    public static CrackResult crackWithWordlist(
            String sid,
            String targetSig,
            String wordlistPath,
            BiConsumer<Long, Double> progressCallback,
            AtomicBoolean cancelFlag
    ) throws IOException {

        long start = System.nanoTime();
        long attempts = 0;
        long lastProgressTime = start;

        try (BufferedReader reader = new BufferedReader(new FileReader(wordlistPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for cancellation
                if (cancelFlag != null && cancelFlag.get()) {
                    double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
                    return new CrackResult(null, attempts, elapsed);
                }

                String secret = line.trim();
                if (secret.isEmpty()) {
                    continue;
                }

                attempts++;

                if (signatureMatches(sid, targetSig, secret)) {
                    double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
                    return new CrackResult(secret, attempts, elapsed);
                }

                // Progress callback every 500ms
                long now = System.nanoTime();
                if (progressCallback != null && (now - lastProgressTime) > 500_000_000L) {
                    double elapsed = (now - start) / 1_000_000_000.0;
                    double speed = elapsed > 0 ? attempts / elapsed : 0;
                    progressCallback.accept(attempts, speed);
                    lastProgressTime = now;
                }
            }
        }

        double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;
        return new CrackResult(null, attempts, elapsed);
    }

    /**
     * Count lines in a wordlist file.
     */
    public static long countWordlistLines(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            long count = 0;
            while (reader.readLine() != null) {
                count++;
            }
            return count;
        } catch (IOException e) {
            return -1;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Session Decoding
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Attempt to decode session data from the SID.
     */
    public static DecodedSession decodeSession(String sid) {
        // Try base64 decode (with padding restoration)
        String padded = sid;
        int padding = 4 - (sid.length() % 4);
        if (padding != 4) {
            padded = sid + "====".substring(0, padding);
        }

        byte[] decoded = null;
        try {
            decoded = Base64.getDecoder().decode(padded);
        } catch (Exception e) {
            try {
                decoded = Base64.getUrlDecoder().decode(padded);
            } catch (Exception e2) {
                // Not base64
            }
        }

        if (decoded != null) {
            try {
                String decodedStr = new String(decoded, StandardCharsets.UTF_8);

                // Check if it looks like JSON
                String trimmed = decodedStr.trim();
                if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                    (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
                    // Pretty print JSON
                    String pretty = prettyPrintJson(trimmed);
                    return new DecodedSession(sid, decodedStr, "base64-json", pretty);
                }

                // Check if it's printable text
                if (isPrintable(decodedStr)) {
                    return new DecodedSession(sid, decodedStr, "base64-string", null);
                }

                // Binary data - show as hex
                String hex = bytesToHex(decoded);
                return new DecodedSession(sid, hex, "base64-binary", null);

            } catch (Exception e) {
                // Binary data
                String hex = bytesToHex(decoded);
                return new DecodedSession(sid, hex, "base64-binary", null);
            }
        }

        // Not base64 - probably a session store key (Redis, etc.)
        return new DecodedSession(sid, sid, "session-store-key", null);
    }

    private static boolean isPrintable(String s) {
        for (char c : s.toCharArray()) {
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                return false;
            }
        }
        return true;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Simple JSON pretty printer (no external dependencies).
     */
    private static String prettyPrintJson(String json) {
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inString = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inString = !inString;
                sb.append(c);
            } else if (!inString) {
                switch (c) {
                    case '{':
                    case '[':
                        sb.append(c);
                        sb.append('\n');
                        indent++;
                        sb.append("  ".repeat(indent));
                        break;
                    case '}':
                    case ']':
                        sb.append('\n');
                        indent--;
                        sb.append("  ".repeat(indent));
                        sb.append(c);
                        break;
                    case ',':
                        sb.append(c);
                        sb.append('\n');
                        sb.append("  ".repeat(indent));
                        break;
                    case ':':
                        sb.append(c);
                        sb.append(' ');
                        break;
                    case ' ':
                    case '\n':
                    case '\r':
                    case '\t':
                        // Skip whitespace outside strings
                        break;
                    default:
                        sb.append(c);
                }
            } else {
                sb.append(c);
            }
        }

        return sb.toString();
    }
}

