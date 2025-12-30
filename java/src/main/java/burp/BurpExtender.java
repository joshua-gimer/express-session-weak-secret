package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Express Session Cracker - Burp Suite Extension
 *
 * Features:
 * - Passive capture of connect.sid cookies
 * - Wordlist-based secret cracking with speed stats
 * - Quick check against common default secrets
 * - Cookie forger to create signed sessions
 * - Session data decoder
 * - Manual cookie input
 * - Context menu integration
 * - Export capabilities
 */
public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // UI
    private ExpressCrackerTab mainTab;

    // Data storage (thread-safe)
    private final List<CapturedCookie> capturedCookies = new CopyOnWriteArrayList<>();
    private final Map<String, String> discoveredSecrets = new ConcurrentHashMap<>();  // sig -> secret

    /**
     * Represents a captured cookie.
     */
    public static class CapturedCookie {
        public final String url;
        public final String cookieValue;
        public final String sid;
        public final String signature;

        public CapturedCookie(String url, String cookieValue, String sid, String signature) {
            this.url = url;
            this.cookieValue = cookieValue;
            this.sid = sid;
            this.signature = signature;
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName("Express Session Cracker");

        // Build UI on EDT
        SwingUtilities.invokeLater(() -> {
            mainTab = new ExpressCrackerTab(this);
            callbacks.addSuiteTab(this);
        });

        // Register listeners
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);

        stdout.println("[*] Express Session Cracker loaded");
        stdout.println("[*] Monitoring for connect.sid cookies...");
        stdout.println("[*] Right-click requests to send cookies to cracker");
        stdout.println("[*] Common secrets database: " + CommonSecrets.SECRETS.size() + " entries");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ITab Implementation
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public String getTabCaption() {
        return "Express Cracker";
    }

    @Override
    public Component getUiComponent() {
        return mainTab;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IHttpListener Implementation
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return;
        }

        byte[] response = messageInfo.getResponse();
        if (response == null) {
            return;
        }

        IResponseInfo respInfo = helpers.analyzeResponse(response);
        List<String> headers = respInfo.getHeaders();

        for (String header : headers) {
            if (!header.toLowerCase().startsWith("set-cookie:")) {
                continue;
            }

            String headerValue = header.substring("Set-Cookie:".length()).trim();
            String lowerValue = headerValue.toLowerCase();

            if (!lowerValue.startsWith("connect.sid=")) {
                continue;
            }

            // Parse cookie attributes
            String[] parts = headerValue.split(";");
            String cookieKV = parts[0].trim();
            List<String> attrs = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                attrs.add(parts[i].trim());
            }

            boolean httpOnly = attrs.stream().anyMatch(a -> a.equalsIgnoreCase("httponly"));
            boolean secure = attrs.stream().anyMatch(a -> a.equalsIgnoreCase("secure"));
            String sameSite = attrs.stream()
                    .filter(a -> a.toLowerCase().startsWith("samesite="))
                    .findFirst()
                    .map(a -> a.split("=", 2)[1])
                    .orElse(null);

            String url = getServiceUrl(messageInfo);

            stdout.println("[*] Found connect.sid on " + url);
            stdout.println("    HttpOnly=" + httpOnly + " Secure=" + secure +
                    " SameSite=" + (sameSite != null ? sameSite : "NONE/unspecified"));

            // Flag missing security attributes
            if (!httpOnly || !secure) {
                List<String> problems = new ArrayList<>();
                if (!httpOnly) problems.add("missing HttpOnly");
                if (!secure) problems.add("missing Secure");
                stderr.println("[!] Weak flags on " + url + ": " + String.join(", ", problems));
            }

            // Extract and store cookie for cracking
            try {
                String cookieValue = cookieKV.split("=", 2)[1];
                CookieUtils.ParsedCookie parsed = CookieUtils.parse(cookieValue);

                // Avoid duplicates
                boolean exists = capturedCookies.stream()
                        .anyMatch(c -> c.signature.equals(parsed.signature));

                if (!exists) {
                    CapturedCookie captured = new CapturedCookie(url, cookieValue, parsed.sid, parsed.signature);
                    capturedCookies.add(captured);

                    // Update UI
                    if (mainTab != null) {
                        SwingUtilities.invokeLater(() -> mainTab.addCookieToTable(captured));
                    }

                    stdout.println("[+] Cookie captured for cracking");
                }
            } catch (Exception e) {
                stderr.println("[!] Failed to parse cookie: " + e.getMessage());
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IContextMenuFactory Implementation
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return null;
        }

        JMenuItem menuItem = new JMenuItem("Send cookie to Express Cracker");
        menuItem.addActionListener(e -> {
            int found = extractCookiesFromMessages(messages);
            if (mainTab != null) {
                if (found > 0) {
                    mainTab.logResult("[+] Added " + found + " cookie(s) from context menu");
                } else {
                    mainTab.logResult("[*] No new connect.sid cookies found in selected messages");
                }
            }
        });

        items.add(menuItem);
        return items;
    }

    /**
     * Extract connect.sid cookies from HTTP messages.
     */
    private int extractCookiesFromMessages(IHttpRequestResponse[] messages) {
        int found = 0;

        for (IHttpRequestResponse message : messages) {
            // Check request Cookie header
            byte[] request = message.getRequest();
            if (request != null) {
                IRequestInfo reqInfo = helpers.analyzeRequest(request);
                for (String header : reqInfo.getHeaders()) {
                    if (header.toLowerCase().startsWith("cookie:")) {
                        found += extractFromCookieHeader(header.substring(7).trim(), message);
                    }
                }
            }

            // Check response Set-Cookie headers
            byte[] response = message.getResponse();
            if (response != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(response);
                for (String header : respInfo.getHeaders()) {
                    if (header.toLowerCase().startsWith("set-cookie:")) {
                        String value = header.substring("Set-Cookie:".length()).trim();
                        if (value.toLowerCase().startsWith("connect.sid=")) {
                            found += extractFromSetCookie(value, message);
                        }
                    }
                }
            }
        }

        return found;
    }

    private int extractFromCookieHeader(String cookieStr, IHttpRequestResponse message) {
        int found = 0;
        for (String part : cookieStr.split(";")) {
            part = part.trim();
            if (part.toLowerCase().startsWith("connect.sid=")) {
                try {
                    String cookieValue = part.split("=", 2)[1];
                    found += addCookieIfNew(cookieValue, message);
                } catch (Exception ignored) {}
            }
        }
        return found;
    }

    private int extractFromSetCookie(String setCookieValue, IHttpRequestResponse message) {
        try {
            String cookieValue = setCookieValue.split(";")[0].split("=", 2)[1];
            return addCookieIfNew(cookieValue, message);
        } catch (Exception e) {
            return 0;
        }
    }

    private int addCookieIfNew(String cookieValue, IHttpRequestResponse message) {
        try {
            CookieUtils.ParsedCookie parsed = CookieUtils.parse(cookieValue);

            boolean exists = capturedCookies.stream()
                    .anyMatch(c -> c.signature.equals(parsed.signature));

            if (!exists) {
                String url = getServiceUrl(message);
                CapturedCookie captured = new CapturedCookie(url, cookieValue, parsed.sid, parsed.signature);
                capturedCookies.add(captured);

                if (mainTab != null) {
                    SwingUtilities.invokeLater(() -> mainTab.addCookieToTable(captured));
                }
                return 1;
            }
        } catch (Exception ignored) {}
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utility Methods
    // ─────────────────────────────────────────────────────────────────────────

    private String getServiceUrl(IHttpRequestResponse message) {
        try {
            IHttpService service = message.getHttpService();
            return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
        } catch (Exception e) {
            return "<unknown>";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public Accessors (for UI)
    // ─────────────────────────────────────────────────────────────────────────

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public List<CapturedCookie> getCapturedCookies() {
        return capturedCookies;
    }

    public Map<String, String> getDiscoveredSecrets() {
        return discoveredSecrets;
    }

    public void addDiscoveredSecret(String signature, String secret) {
        discoveredSecrets.put(signature, secret);
        callbacks.issueAlert("Express secret found: " + secret);
    }

    public void clearCapturedCookies() {
        capturedCookies.clear();
    }

    public void log(String message) {
        stdout.println(message);
    }

    public void logError(String message) {
        stderr.println(message);
    }

    /**
     * Add a manually entered cookie.
     */
    public boolean addManualCookie(String cookieValue) {
        try {
            CookieUtils.ParsedCookie parsed = CookieUtils.parse(cookieValue);

            boolean exists = capturedCookies.stream()
                    .anyMatch(c -> c.signature.equals(parsed.signature));

            if (exists) {
                return false;
            }

            CapturedCookie captured = new CapturedCookie("manual-entry", cookieValue, parsed.sid, parsed.signature);
            capturedCookies.add(captured);

            if (mainTab != null) {
                SwingUtilities.invokeLater(() -> mainTab.addCookieToTable(captured));
            }

            return true;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse cookie: " + e.getMessage());
        }
    }
}

