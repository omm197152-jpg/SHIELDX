import json
import threading
import queue
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "SHIELDX"
VERSION = "1.0.0"

HEADER_RULES = [
    ("Content-Security-Policy", "CSP", 20,
     "Defines which sources a browser may load content from. Helps reduce cross-site scripting (XSS) risk.",
     "Configure a restrictive Content-Security-Policy based on the resources your site actually needs."),
    ("Strict-Transport-Security", "HSTS", 15,
     "Tells browsers to use HTTPS for future visits.",
     "Enable HSTS after confirming the site and all relevant subdomains work correctly over HTTPS."),
    ("X-Frame-Options", "Clickjacking", 12,
     "Controls whether the site can be embedded in frames.",
     "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors."),
    ("X-Content-Type-Options", "MIME Sniffing", 10,
     "Prevents browsers from guessing a response's MIME type.",
     "Set X-Content-Type-Options: nosniff."),
    ("Referrer-Policy", "Referrer Privacy", 10,
     "Controls how much referrer information is shared with other sites.",
     "Consider strict-origin-when-cross-origin or no-referrer, depending on site requirements."),
    ("Permissions-Policy", "Browser Permissions", 10,
     "Restricts access to browser features such as camera, microphone and geolocation.",
     "Define a Permissions-Policy that disables features your site does not use."),
    ("Cross-Origin-Opener-Policy", "COOP", 8,
     "Helps isolate a browsing context from cross-origin documents.",
     "Review whether same-origin or same-origin-allow-popups is suitable for your application."),
    ("Cross-Origin-Resource-Policy", "CORP", 8,
     "Controls which origins may load a resource.",
     "Set an appropriate cross-origin resource policy for the resources served."),
    ("Cross-Origin-Embedder-Policy", "COEP", 7,
     "Controls loading of cross-origin resources in an isolated context.",
     "Review require-corp or credentialless if your application needs cross-origin isolation."),
]

BG = "#08111F"
PANEL = "#101D30"
PANEL2 = "#14243A"
TEXT = "#E8F1FF"
MUTED = "#91A4BD"
CYAN = "#32D8F2"
PURPLE = "#9B8CFF"
GREEN = "#35D39A"
YELLOW = "#F6C96B"
RED = "#FF7185"

class ShieldXApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} | Web Security Header Analyzer")
        self.root.geometry("1180x780")
        self.root.minsize(980, 680)
        self.root.configure(bg=BG)
        self.events = queue.Queue()
        self.results = None
        self.scanning = False
        self._setup_style()
        self._build_ui()
        self.root.after(100, self._process_events)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=34, borderwidth=0,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL2, foreground=CYAN,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#203D5C")],
                  foreground=[("selected", TEXT)])
        style.configure("Horizontal.TProgressbar", troughcolor=PANEL2,
                        background=CYAN, bordercolor=PANEL2, lightcolor=CYAN,
                        darkcolor=CYAN)

    def _label(self, parent, text, size=10, color=TEXT, bold=False):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def _card(self, parent, bg=PANEL, padx=16, pady=14):
        frame = tk.Frame(parent, bg=bg, highlightthickness=1,
                         highlightbackground="#20334D")
        frame.pack_propagate(False)
        return frame

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 12))
        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left")
        self._label(brand, "◈  SHIELDX", 23, CYAN, True).pack(anchor="w")
        self._label(brand, "WEB SECURITY HEADER ANALYZER  •  v1.0.0", 8, MUTED, True).pack(anchor="w", pady=(2, 0))
        self._label(header, "DEFENSIVE WEB SECURITY TOOL", 9, PURPLE, True).pack(side="right", pady=12)

        target = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground="#20334D")
        target.pack(fill="x", padx=28, pady=8)
        self._label(target, "TARGET WEBSITE", 9, MUTED, True).pack(anchor="w", padx=18, pady=(14, 5))
        row = tk.Frame(target, bg=PANEL)
        row.pack(fill="x", padx=18, pady=(0, 15))
        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(row, textvariable=self.url_var, bg="#0B1728", fg=TEXT,
                                  insertbackground=CYAN, relief="flat", font=("Segoe UI", 12),
                                  highlightthickness=1, highlightbackground="#29415F",
                                  highlightcolor=CYAN)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=12, padx=(0, 12))
        self.url_entry.insert(0, "https://example.com")
        self.scan_btn = tk.Button(row, text="  SCAN WEBSITE  →  ", command=self.start_scan,
                                  bg=CYAN, fg="#04111E", activebackground="#78E8F8",
                                  activeforeground="#04111E", relief="flat", bd=0,
                                  font=("Segoe UI", 10, "bold"), cursor="hand2", padx=16, pady=12)
        self.scan_btn.pack(side="right")

        stats = tk.Frame(self.root, bg=BG)
        stats.pack(fill="x", padx=28, pady=8)
        self.score_card = self._stat_card(stats, "SECURITY SCORE", "—", "Waiting for scan", CYAN)
        self.present_card = self._stat_card(stats, "HEADERS PRESENT", "—", "Security controls found", GREEN)
        self.missing_card = self._stat_card(stats, "HEADERS MISSING", "—", "Review recommendations", RED)
        self.status_card = self._stat_card(stats, "HTTP STATUS", "—", "Response status", PURPLE)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=28, pady=(8, 10))
        left = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground="#20334D")
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(body, bg=PANEL, width=310, highlightthickness=1, highlightbackground="#20334D")
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._label(left, "HEADER INSPECTION", 11, TEXT, True).pack(anchor="w", padx=16, pady=(15, 4))
        self._label(left, "Nine recommended HTTP response headers", 9, MUTED).pack(anchor="w", padx=16, pady=(0, 12))
        columns = ("header", "status", "value")
        self.table = ttk.Treeview(left, columns=columns, show="headings", height=11)
        self.table.heading("header", text="SECURITY HEADER")
        self.table.heading("status", text="STATUS")
        self.table.heading("value", text="DETECTED VALUE")
        self.table.column("header", width=205, anchor="w")
        self.table.column("status", width=105, anchor="center")
        self.table.column("value", width=360, anchor="w")
        self.table.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.table.tag_configure("present", foreground=GREEN)
        self.table.tag_configure("missing", foreground=RED)

        self._label(right, "SCAN ACTIVITY", 11, TEXT, True).pack(anchor="w", padx=16, pady=(15, 8))
        self.progress = ttk.Progressbar(right, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=16, pady=(0, 10))
        self.log = tk.Text(right, height=15, bg="#0A1626", fg=MUTED, insertbackground=CYAN,
                           relief="flat", bd=0, font=("Consolas", 8), wrap="word",
                           padx=10, pady=10)
        self.log.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.log.configure(state="disabled")
        actions = tk.Frame(right, bg=PANEL)
        actions.pack(fill="x", padx=14, pady=(0, 14))
        self.export_btn = tk.Button(actions, text="EXPORT JSON REPORT", command=self.export_report,
                                    state="disabled", bg="#243B59", fg=TEXT,
                                    activebackground="#315477", relief="flat", bd=0,
                                    font=("Segoe UI", 9, "bold"), cursor="hand2", pady=10)
        self.export_btn.pack(fill="x")
        self._label(self.root, "Use only on websites you own or are authorized to assess. Results are informational, not a penetration test.",
                    8, MUTED).pack(anchor="w", padx=30, pady=(0, 12))
        self._log("SHIELDX initialized. Enter a website URL to begin.")
        self._log("Checks are passive HTTP response-header checks only.")

    def _stat_card(self, parent, title, value, subtitle, accent):
        card = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground="#20334D")
        card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        tk.Frame(card, bg=accent, height=3).pack(fill="x")
        self._label(card, title, 8, MUTED, True).pack(anchor="w", padx=14, pady=(10, 2))
        value_label = self._label(card, value, 21, accent, True)
        value_label.pack(anchor="w", padx=14)
        self._label(card, subtitle, 8, MUTED).pack(anchor="w", padx=14, pady=(0, 11))
        return value_label

    def _log(self, message):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{stamp}]  {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _normalize_url(self, raw):
        raw = raw.strip()
        if not raw:
            raise ValueError("Enter a website URL.")
        if not re.match(r"^https?://", raw, re.I):
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Enter a valid http:// or https:// website URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not supported.")
        return raw

    def start_scan(self):
        if self.scanning:
            return
        try:
            url = self._normalize_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid URL", str(exc))
            return
        self.url_var.set(url)
        self.scanning = True
        self.results = None
        self.scan_btn.configure(state="disabled", text="  SCANNING...  ")
        self.export_btn.configure(state="disabled")
        self.progress.start(12)
        for item in self.table.get_children():
            self.table.delete(item)
        self.score_card.configure(text="...")
        self.present_card.configure(text="...")
        self.missing_card.configure(text="...")
        self.status_card.configure(text="...")
        self._log(f"Starting header inspection: {url}")
        threading.Thread(target=self._scan_worker, args=(url,), daemon=True).start()

    def _scan_worker(self, url):
        try:
            self.events.put(("log", "Sending HTTP GET request (10-second timeout)..."))
            response = requests.get(
                url, timeout=10, allow_redirects=True,
                headers={"User-Agent": "SHIELDX/1.0 (defensive-security-header-checker)"}
            )
            headers = {k.lower(): v for k, v in response.headers.items()}
            findings = []
            score = 0
            for name, short, weight, explanation, recommendation in HEADER_RULES:
                value = headers.get(name.lower())
                present = bool(value and value.strip())
                if present:
                    score += weight
                findings.append({
                    "header": name, "category": short,
                    "status": "PRESENT" if present else "MISSING",
                    "value": value or "",
                    "weight": weight,
                    "explanation": explanation,
                    "recommendation": recommendation
                })
            payload = {
                "tool": APP_NAME, "version": VERSION,
                "scanned_url": url, "final_url": response.url,
                "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
                "http_status": response.status_code,
                "https": urlparse(response.url).scheme == "https",
                "security_score": score,
                "headers_present": sum(x["status"] == "PRESENT" for x in findings),
                "headers_missing": sum(x["status"] == "MISSING" for x in findings),
                "findings": findings,
                "disclaimer": "Informational passive header analysis; not a complete security assessment."
            }
            self.events.put(("result", payload))
        except requests.exceptions.SSLError as exc:
            self.events.put(("error", f"TLS/SSL error: {exc}"))
        except requests.exceptions.Timeout:
            self.events.put(("error", "Request timed out after 10 seconds."))
        except requests.exceptions.RequestException as exc:
            self.events.put(("error", f"Request failed: {exc}"))
        except Exception as exc:
            self.events.put(("error", f"Unexpected error: {exc}"))

    def _process_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "log":
                    self._log(data)
                elif kind == "result":
                    self._show_results(data)
                elif kind == "error":
                    self._finish_scan()
                    self._log("Scan failed: " + data)
                    messagebox.showerror("Scan Error", data)
        except queue.Empty:
            pass
        self.root.after(100, self._process_events)

    def _show_results(self, data):
        self.results = data
        self._finish_scan()
        for finding in data["findings"]:
            value = finding["value"] or "—"
            if len(value) > 75:
                value = value[:72] + "..."
            self.table.insert("", "end",
                              values=(finding["header"], finding["status"], value),
                              tags=("present" if finding["status"] == "PRESENT" else "missing",))
        score = data["security_score"]
        self.score_card.configure(text=f"{score}/100")
        self.present_card.configure(text=str(data["headers_present"]))
        self.missing_card.configure(text=str(data["headers_missing"]))
        self.status_card.configure(text=str(data["http_status"]))
        self.export_btn.configure(state="normal")
        self._log(f"HTTP response received: {data['http_status']}")
        self._log(f"Analysis complete. Score: {score}/100")
        self._log(f"Present: {data['headers_present']} | Missing: {data['headers_missing']}")
        self._log("Final response URL: " + data["final_url"])
        messagebox.showinfo("Scan Complete", f"SHIELDX analysis completed.\nSecurity header score: {score}/100")

    def _finish_scan(self):
        self.scanning = False
        self.progress.stop()
        self.scan_btn.configure(state="normal", text="  SCAN WEBSITE  →  ")

    def export_report(self):
        if not self.results:
            return
        suggested = "shieldx_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile=suggested,
            filetypes=[("JSON report", "*.json")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self._log("Report exported: " + path)
            messagebox.showinfo("Export Successful", "JSON report saved successfully.")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))


def main():
    root = tk.Tk()
    ShieldXApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
