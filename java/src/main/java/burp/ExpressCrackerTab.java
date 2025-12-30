package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main UI tab for the Express Session Cracker extension.
 */
public class ExpressCrackerTab extends JPanel {

    private final BurpExtender extender;

    // Capture & Crack tab components
    private JTextField wordlistField;
    private JLabel wordlistInfoLabel;
    private JCheckBox quickCheckBox;
    private DefaultTableModel tableModel;
    private JTable cookiesTable;
    private JTextArea resultsArea;
    private JButton cancelButton;
    private JLabel statusLabel;

    // Forger tab components
    private JTextField forgeSecretField;
    private JTextField forgeSidField;
    private JTextField forgeOutputField;
    private JTextField forgeEncodedField;
    private JTextField forgeHeaderField;

    // Decoder tab components
    private JTextField decodeInputField;
    private JTextArea decodeOutputArea;

    // Cracking state
    private final AtomicBoolean cracking = new AtomicBoolean(false);
    private final AtomicBoolean cancelRequested = new AtomicBoolean(false);

    public ExpressCrackerTab(BurpExtender extender) {
        this.extender = extender;
        buildUI();
    }

    private void buildUI() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create tabbed pane
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Capture & Crack", buildCrackPanel());
        tabs.addTab("Cookie Forger", buildForgerPanel());
        tabs.addTab("Session Decoder", buildDecoderPanel());
        tabs.addTab("Settings & Export", buildSettingsPanel());

        add(tabs, BorderLayout.CENTER);

        // Status bar
        statusLabel = new JLabel("Ready | Common secrets: " + CommonSecrets.SECRETS.size() +
                " | Right-click requests to add cookies");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(statusLabel, BorderLayout.SOUTH);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Capture & Crack Panel
    // ─────────────────────────────────────────────────────────────────────────

    private JPanel buildCrackPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Top: Wordlist config
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createTitledBorder("Wordlist Configuration"));

        JPanel wordlistRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        wordlistRow.add(new JLabel("Wordlist:"));

        wordlistField = new JTextField(35);
        wordlistField.setToolTipText("Path to wordlist file (one secret per line)");
        wordlistRow.add(wordlistField);

        JButton browseBtn = new JButton("Browse...");
        browseBtn.addActionListener(e -> browseWordlist());
        wordlistRow.add(browseBtn);

        wordlistInfoLabel = new JLabel("");
        wordlistRow.add(wordlistInfoLabel);

        topPanel.add(wordlistRow, BorderLayout.NORTH);

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        quickCheckBox = new JCheckBox("Try common secrets first", true);
        quickCheckBox.setToolTipText("Check " + CommonSecrets.SECRETS.size() + " common secrets before wordlist");
        optionsRow.add(quickCheckBox);
        topPanel.add(optionsRow, BorderLayout.SOUTH);

        panel.add(topPanel, BorderLayout.NORTH);

        // Center: Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.5);

        // Cookies table
        JPanel cookiesPanel = new JPanel(new BorderLayout(5, 5));
        cookiesPanel.setBorder(BorderFactory.createTitledBorder("Captured Cookies"));

        tableModel = new DefaultTableModel(
                new String[]{"#", "URL", "SID (truncated)", "Signature", "Secret"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        cookiesTable = new JTable(tableModel);
        cookiesTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        cookiesTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        cookiesTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        cookiesTable.getColumnModel().getColumn(3).setPreferredWidth(180);
        cookiesTable.getColumnModel().getColumn(4).setPreferredWidth(120);

        // Double-click to decode
        cookiesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = cookiesTable.getSelectedRow();
                    if (row >= 0 && row < extender.getCapturedCookies().size()) {
                        BurpExtender.CapturedCookie cookie = extender.getCapturedCookies().get(row);
                        decodeInputField.setText(cookie.cookieValue);
                        decodeAndDisplay(cookie.cookieValue);
                        // Switch to decoder tab
                        ((JTabbedPane) getComponent(0)).setSelectedIndex(2);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(cookiesTable);
        tableScroll.setPreferredSize(new Dimension(800, 180));
        cookiesPanel.add(tableScroll, BorderLayout.CENTER);

        // Cookie buttons
        JPanel cookieBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton addManualBtn = new JButton("Add Cookie Manually");
        addManualBtn.addActionListener(e -> addManualCookie());
        cookieBtnPanel.add(addManualBtn);

        JButton crackBtn = new JButton("Crack Selected");
        crackBtn.addActionListener(e -> crackSelected());
        cookieBtnPanel.add(crackBtn);

        JButton crackAllBtn = new JButton("Crack All");
        crackAllBtn.addActionListener(e -> crackAll());
        cookieBtnPanel.add(crackAllBtn);

        JButton quickCheckBtn = new JButton("Quick Check Only");
        quickCheckBtn.setToolTipText("Only try common secrets, no wordlist");
        quickCheckBtn.addActionListener(e -> quickCheckOnly());
        cookieBtnPanel.add(quickCheckBtn);

        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancelCracking());
        cancelButton.setEnabled(false);
        cookieBtnPanel.add(cancelButton);

        JButton clearBtn = new JButton("Clear Table");
        clearBtn.addActionListener(e -> clearTable());
        cookieBtnPanel.add(clearBtn);

        cookiesPanel.add(cookieBtnPanel, BorderLayout.SOUTH);
        splitPane.setTopComponent(cookiesPanel);

        // Results area
        JPanel resultsPanel = new JPanel(new BorderLayout(5, 5));
        resultsPanel.setBorder(BorderFactory.createTitledBorder("Cracking Results"));

        resultsArea = new JTextArea();
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane resultsScroll = new JScrollPane(resultsArea);
        resultsScroll.setPreferredSize(new Dimension(800, 180));
        resultsPanel.add(resultsScroll, BorderLayout.CENTER);

        JPanel resultsBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton copyResultsBtn = new JButton("Copy Results");
        copyResultsBtn.addActionListener(e -> copyToClipboard(resultsArea.getText()));
        resultsBtnPanel.add(copyResultsBtn);

        JButton clearResultsBtn = new JButton("Clear Results");
        clearResultsBtn.addActionListener(e -> resultsArea.setText(""));
        resultsBtnPanel.add(clearResultsBtn);

        resultsPanel.add(resultsBtnPanel, BorderLayout.SOUTH);
        splitPane.setBottomComponent(resultsPanel);

        panel.add(splitPane, BorderLayout.CENTER);

        return panel;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cookie Forger Panel
    // ─────────────────────────────────────────────────────────────────────────

    private JPanel buildForgerPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel instructions = new JLabel(
                "<html><b>Cookie Forger</b> - Create signed connect.sid cookies using a known secret</html>");
        panel.add(instructions, BorderLayout.NORTH);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("Forge Cookie"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Secret field
        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(new JLabel("Secret:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        forgeSecretField = new JTextField(40);
        forgeSecretField.setToolTipText("The session secret (discovered or known)");
        formPanel.add(forgeSecretField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JButton useDiscoveredBtn = new JButton("Use Discovered");
        useDiscoveredBtn.addActionListener(e -> useDiscoveredSecret());
        formPanel.add(useDiscoveredBtn, gbc);

        // Session ID field
        gbc.gridx = 0;
        gbc.gridy = 1;
        formPanel.add(new JLabel("Session ID:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        forgeSidField = new JTextField(40);
        forgeSidField.setToolTipText("Session ID to sign (e.g., generated UUID or custom data)");
        formPanel.add(forgeSidField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JButton genUuidBtn = new JButton("Generate UUID");
        genUuidBtn.addActionListener(e -> forgeSidField.setText(CookieUtils.generateUUID()));
        formPanel.add(genUuidBtn, gbc);

        // Generate button
        gbc.gridx = 1;
        gbc.gridy = 2;
        JButton forgeBtn = new JButton("Generate Signed Cookie");
        forgeBtn.addActionListener(e -> forgeCookie());
        formPanel.add(forgeBtn, gbc);

        // Cookie value output
        gbc.gridx = 0;
        gbc.gridy = 3;
        formPanel.add(new JLabel("Cookie Value:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        forgeOutputField = new JTextField(40);
        forgeOutputField.setEditable(false);
        forgeOutputField.setToolTipText("The signed cookie value (without URL encoding)");
        formPanel.add(forgeOutputField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JButton copyRawBtn = new JButton("Copy");
        copyRawBtn.addActionListener(e -> copyToClipboard(forgeOutputField.getText()));
        formPanel.add(copyRawBtn, gbc);

        // URL encoded output
        gbc.gridx = 0;
        gbc.gridy = 4;
        formPanel.add(new JLabel("URL Encoded:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        forgeEncodedField = new JTextField(40);
        forgeEncodedField.setEditable(false);
        forgeEncodedField.setToolTipText("URL-encoded cookie value (for use in Cookie header)");
        formPanel.add(forgeEncodedField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JButton copyEncodedBtn = new JButton("Copy");
        copyEncodedBtn.addActionListener(e -> copyToClipboard(forgeEncodedField.getText()));
        formPanel.add(copyEncodedBtn, gbc);

        // Full header output
        gbc.gridx = 0;
        gbc.gridy = 5;
        formPanel.add(new JLabel("Full Header:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        forgeHeaderField = new JTextField(40);
        forgeHeaderField.setEditable(false);
        forgeHeaderField.setToolTipText("Complete Cookie header ready to use");
        formPanel.add(forgeHeaderField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JButton copyHeaderBtn = new JButton("Copy");
        copyHeaderBtn.addActionListener(e -> copyToClipboard(forgeHeaderField.getText()));
        formPanel.add(copyHeaderBtn, gbc);

        panel.add(formPanel, BorderLayout.CENTER);

        return panel;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Session Decoder Panel
    // ─────────────────────────────────────────────────────────────────────────

    private JPanel buildDecoderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Input section
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Cookie Input"));

        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        inputRow.add(new JLabel("Cookie/SID:"));

        decodeInputField = new JTextField(50);
        decodeInputField.setToolTipText("Paste connect.sid cookie value or just the SID portion");
        inputRow.add(decodeInputField);

        JButton decodeBtn = new JButton("Decode");
        decodeBtn.addActionListener(e -> decodeAndDisplay(decodeInputField.getText()));
        inputRow.add(decodeBtn);

        inputPanel.add(inputRow, BorderLayout.CENTER);
        panel.add(inputPanel, BorderLayout.NORTH);

        // Output section
        JPanel outputPanel = new JPanel(new BorderLayout(5, 5));
        outputPanel.setBorder(BorderFactory.createTitledBorder("Decoded Session Data"));

        decodeOutputArea = new JTextArea(15, 60);
        decodeOutputArea.setEditable(false);
        decodeOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputPanel.add(new JScrollPane(decodeOutputArea), BorderLayout.CENTER);

        panel.add(outputPanel, BorderLayout.CENTER);

        return panel;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Settings & Export Panel
    // ─────────────────────────────────────────────────────────────────────────

    private JPanel buildSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Export section
        JPanel exportPanel = new JPanel();
        exportPanel.setLayout(new BoxLayout(exportPanel, BoxLayout.Y_AXIS));
        exportPanel.setBorder(BorderFactory.createTitledBorder("Export"));

        JPanel exportRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton exportCookiesBtn = new JButton("Export Cookies as JSON");
        exportCookiesBtn.addActionListener(e -> exportCookiesAsJson());
        exportRow.add(exportCookiesBtn);

        JButton exportSecretsBtn = new JButton("Export Discovered Secrets");
        exportSecretsBtn.addActionListener(e -> exportSecrets());
        exportRow.add(exportSecretsBtn);

        exportPanel.add(exportRow);
        panel.add(exportPanel, BorderLayout.NORTH);

        // Common secrets list
        JPanel secretsPanel = new JPanel(new BorderLayout(5, 5));
        secretsPanel.setBorder(BorderFactory.createTitledBorder(
                "Common Secrets List (" + CommonSecrets.SECRETS.size() + " entries)"));

        JTextArea secretsArea = new JTextArea(15, 60);
        secretsArea.setEditable(false);
        secretsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        secretsArea.setText(String.join("\n", CommonSecrets.SECRETS));
        secretsPanel.add(new JScrollPane(secretsArea), BorderLayout.CENTER);

        panel.add(secretsPanel, BorderLayout.CENTER);

        return panel;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Action Handlers
    // ─────────────────────────────────────────────────────────────────────────

    private void browseWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Wordlist");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            wordlistField.setText(path);
            updateWordlistInfo();
        }
    }

    private void updateWordlistInfo() {
        String path = wordlistField.getText().trim();
        if (!path.isEmpty()) {
            long count = CookieUtils.countWordlistLines(path);
            if (count >= 0) {
                wordlistInfoLabel.setText(String.format("(%,d lines)", count));
            } else {
                wordlistInfoLabel.setText("(file not found)");
            }
        } else {
            wordlistInfoLabel.setText("");
        }
    }

    private void addManualCookie() {
        String cookie = JOptionPane.showInputDialog(
                this,
                "Paste connect.sid cookie value:\n(e.g., s%3A... or the full connect.sid=... header)",
                "Add Cookie Manually",
                JOptionPane.PLAIN_MESSAGE
        );

        if (cookie != null && !cookie.trim().isEmpty()) {
            try {
                if (extender.addManualCookie(cookie)) {
                    logResult("[+] Cookie added manually");
                } else {
                    logResult("[!] Cookie already exists in table");
                }
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(
                        this,
                        e.getMessage(),
                        "Parse Error",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private void crackSelected() {
        if (cracking.get()) {
            logResult("[!] Already cracking, please wait or cancel");
            return;
        }

        int[] rows = cookiesTable.getSelectedRows();
        if (rows.length == 0) {
            logResult("[!] Please select one or more cookies to crack");
            return;
        }

        startCracking(rows, false);
    }

    private void crackAll() {
        if (cracking.get()) {
            logResult("[!] Already cracking, please wait or cancel");
            return;
        }

        List<BurpExtender.CapturedCookie> cookies = extender.getCapturedCookies();
        if (cookies.isEmpty()) {
            logResult("[!] No cookies captured yet");
            return;
        }

        int[] rows = new int[cookies.size()];
        for (int i = 0; i < cookies.size(); i++) {
            rows[i] = i;
        }

        startCracking(rows, false);
    }

    private void quickCheckOnly() {
        if (cracking.get()) {
            logResult("[!] Already cracking, please wait or cancel");
            return;
        }

        List<BurpExtender.CapturedCookie> cookies = extender.getCapturedCookies();
        if (cookies.isEmpty()) {
            logResult("[!] No cookies captured yet");
            return;
        }

        int[] rows = cookiesTable.getSelectedRows();
        if (rows.length == 0) {
            rows = new int[cookies.size()];
            for (int i = 0; i < cookies.size(); i++) {
                rows[i] = i;
            }
        }

        startCracking(rows, true);
    }

    private void startCracking(int[] rows, boolean quickOnly) {
        String wordlistPath = wordlistField.getText().trim();
        if (!quickOnly && wordlistPath.isEmpty()) {
            logResult("[!] Please specify a wordlist path");
            return;
        }

        List<BurpExtender.CapturedCookie> cookies = extender.getCapturedCookies();
        cracking.set(true);
        cancelRequested.set(false);
        cancelButton.setEnabled(true);

        new Thread(() -> {
            try {
                logResult("=" .repeat(70));
                logResult("[*] Starting crack attempt on " + rows.length + " cookie(s)");
                if (quickCheckBox.isSelected()) {
                    logResult("[*] Will try " + CommonSecrets.SECRETS.size() + " common secrets first");
                }
                if (!quickOnly && !wordlistPath.isEmpty()) {
                    logResult("[*] Wordlist: " + wordlistPath);
                }
                logResult("=" .repeat(70));

                for (int rowIndex : rows) {
                    if (cancelRequested.get()) {
                        logResult("[!] Cancelled by user");
                        break;
                    }

                    if (rowIndex < 0 || rowIndex >= cookies.size()) {
                        continue;
                    }

                    BurpExtender.CapturedCookie cookie = cookies.get(rowIndex);
                    logResult("");
                    logResult("[*] Cracking cookie from: " + cookie.url);
                    logResult("[*] SID length: " + cookie.sid.length() + ", Signature: " + cookie.signature);

                    String foundSecret = null;
                    long totalAttempts = 0;

                    // Try common secrets first
                    if (quickCheckBox.isSelected()) {
                        setStatus("Quick check: trying common secrets...");
                        CookieUtils.CrackResult result = CookieUtils.crackWithCommonSecrets(
                                cookie.sid, cookie.signature);
                        totalAttempts += result.attempts;

                        if (result.isFound()) {
                            foundSecret = result.secret;
                            logResult("[+] FOUND via common secrets! Secret: " + result.secret);
                            logResult(String.format("[+] Found after %d attempts in %.3fs",
                                    result.attempts, result.elapsedSeconds));
                        }
                    }

                    // Try wordlist if not found
                    if (foundSecret == null && !quickOnly && !wordlistPath.isEmpty()) {
                        setStatus("Cracking: " + cookie.url);

                        try {
                            CookieUtils.CrackResult result = CookieUtils.crackWithWordlist(
                                    cookie.sid,
                                    cookie.signature,
                                    wordlistPath,
                                    (attempts, speed) -> setStatus(
                                            String.format("Tried %,d candidates (%.0f/sec)...", attempts, speed)),
                                    cancelRequested
                            );
                            totalAttempts += result.attempts;

                            if (result.isFound()) {
                                foundSecret = result.secret;
                                logResult("[+] SUCCESS! Secret found: " + result.secret);
                                logResult(String.format("[+] Attempts: %,d in %.2fs (%.0f/sec)",
                                        result.attempts, result.elapsedSeconds, result.getSpeed()));
                            }
                        } catch (IOException e) {
                            logResult("[!] Error reading wordlist: " + e.getMessage());
                        }
                    }

                    if (foundSecret != null) {
                        // Store secret
                        extender.addDiscoveredSecret(cookie.signature, foundSecret);
                        updateTableSecret(cookie.signature, foundSecret);
                    } else if (!cancelRequested.get()) {
                        logResult(String.format("[-] Secret not found (tried %,d candidates)", totalAttempts));
                    }
                }

                logResult("");
                logResult("[*] Cracking complete");
                setStatus("Ready | Common secrets: " + CommonSecrets.SECRETS.size() +
                        " | Right-click requests to add cookies");

            } finally {
                cracking.set(false);
                SwingUtilities.invokeLater(() -> cancelButton.setEnabled(false));
            }
        }).start();
    }

    private void cancelCracking() {
        cancelRequested.set(true);
        logResult("[*] Cancel requested, waiting for current attempt to finish...");
    }

    private void clearTable() {
        if (cracking.get()) {
            logResult("[!] Cannot clear while cracking");
            return;
        }
        extender.clearCapturedCookies();
        tableModel.setRowCount(0);
        logResult("[*] Cookie table cleared");
    }

    private void forgeCookie() {
        String secret = forgeSecretField.getText().trim();
        String sid = forgeSidField.getText().trim();

        if (secret.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a secret",
                    "Missing Secret", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (sid.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a session ID",
                    "Missing SID", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String cookieValue = CookieUtils.signCookie(sid, secret);
        String encodedValue = CookieUtils.urlEncode(cookieValue);
        String fullHeader = "Cookie: connect.sid=" + encodedValue;

        forgeOutputField.setText(cookieValue);
        forgeEncodedField.setText(encodedValue);
        forgeHeaderField.setText(fullHeader);
    }

    private void useDiscoveredSecret() {
        java.util.Collection<String> secrets = extender.getDiscoveredSecrets().values();
        if (secrets.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No secrets discovered yet. Crack some cookies first!",
                    "No Secrets",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] secretArray = secrets.toArray(new String[0]);
        if (secretArray.length == 1) {
            forgeSecretField.setText(secretArray[0]);
        } else {
            String selected = (String) JOptionPane.showInputDialog(
                    this,
                    "Select a discovered secret:",
                    "Choose Secret",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    secretArray,
                    secretArray[0]
            );
            if (selected != null) {
                forgeSecretField.setText(selected);
            }
        }
    }

    private void decodeAndDisplay(String cookieValue) {
        if (cookieValue == null || cookieValue.trim().isEmpty()) {
            return;
        }

        try {
            CookieUtils.ParsedCookie parsed = CookieUtils.parse(cookieValue);
            CookieUtils.DecodedSession decoded = CookieUtils.decodeSession(parsed.sid);

            StringBuilder output = new StringBuilder();
            output.append("=".repeat(50)).append("\n");
            output.append("SESSION DATA ANALYSIS\n");
            output.append("=".repeat(50)).append("\n\n");
            output.append("Raw SID: ").append(decoded.raw).append("\n\n");
            output.append("Type: ").append(decoded.type).append("\n\n");

            if (decoded.decoded != null) {
                output.append("Decoded:\n");
                if (decoded.json != null) {
                    output.append(decoded.json);
                } else {
                    output.append(decoded.decoded);
                }
                output.append("\n");
            }

            output.append("\nSignature: ").append(parsed.signature);

            String knownSecret = extender.getDiscoveredSecrets().get(parsed.signature);
            if (knownSecret != null) {
                output.append("\nKnown Secret: ").append(knownSecret);
            }

            decodeOutputArea.setText(output.toString());

        } catch (Exception e) {
            decodeOutputArea.setText("Error: " + e.getMessage());
        }
    }

    private void exportCookiesAsJson() {
        List<BurpExtender.CapturedCookie> cookies = extender.getCapturedCookies();
        if (cookies.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No cookies to export",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Cookies as JSON");
        chooser.setSelectedFile(new File("express_cookies.json"));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(chooser.getSelectedFile()))) {
                writer.println("[");
                for (int i = 0; i < cookies.size(); i++) {
                    BurpExtender.CapturedCookie c = cookies.get(i);
                    String secret = extender.getDiscoveredSecrets().get(c.signature);

                    writer.println("  {");
                    writer.println("    \"url\": \"" + escapeJson(c.url) + "\",");
                    writer.println("    \"cookie_value\": \"" + escapeJson(c.cookieValue) + "\",");
                    writer.println("    \"sid\": \"" + escapeJson(c.sid) + "\",");
                    writer.println("    \"signature\": \"" + escapeJson(c.signature) + "\",");
                    writer.println("    \"secret\": " + (secret != null ? "\"" + escapeJson(secret) + "\"" : "null"));
                    writer.print("  }");
                    if (i < cookies.size() - 1) {
                        writer.print(",");
                    }
                    writer.println();
                }
                writer.println("]");

                logResult("[+] Exported " + cookies.size() + " cookies to " +
                        chooser.getSelectedFile().getAbsolutePath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportSecrets() {
        java.util.Collection<String> secrets = extender.getDiscoveredSecrets().values();
        if (secrets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No secrets discovered yet",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Discovered Secrets");
        chooser.setSelectedFile(new File("express_secrets.txt"));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(chooser.getSelectedFile()))) {
                writer.println("# Express Session Secrets");
                writer.println("# Exported from Burp Suite");
                writer.println();

                java.util.Set<String> uniqueSecrets = new java.util.HashSet<>(secrets);
                for (String secret : uniqueSecrets) {
                    writer.println(secret);
                }

                logResult("[+] Exported " + uniqueSecrets.size() + " unique secrets to " +
                        chooser.getSelectedFile().getAbsolutePath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utility Methods
    // ─────────────────────────────────────────────────────────────────────────

    public void addCookieToTable(BurpExtender.CapturedCookie cookie) {
        int rowNum = tableModel.getRowCount() + 1;
        String sidDisplay = cookie.sid.length() > 25
                ? cookie.sid.substring(0, 25) + "..."
                : cookie.sid;
        String secret = extender.getDiscoveredSecrets().getOrDefault(cookie.signature, "");

        tableModel.addRow(new Object[]{
                String.valueOf(rowNum),
                cookie.url,
                sidDisplay,
                cookie.signature,
                secret
        });
    }

    private void updateTableSecret(String signature, String secret) {
        SwingUtilities.invokeLater(() -> {
            for (int row = 0; row < tableModel.getRowCount(); row++) {
                if (tableModel.getValueAt(row, 3).equals(signature)) {
                    tableModel.setValueAt(secret, row, 4);
                }
            }
        });
    }

    public void logResult(String message) {
        SwingUtilities.invokeLater(() -> {
            resultsArea.append(message + "\n");
            resultsArea.setCaretPosition(resultsArea.getDocument().getLength());
        });
    }

    private void setStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    private void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
            setStatus("Copied to clipboard");
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

