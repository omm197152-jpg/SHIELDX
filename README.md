# SHIELDX — Web Security Header Analyzer

**Scan Smart. Secure Better.**

SHIELDX is a Python desktop GUI tool that checks a website's HTTP response for commonly recommended security headers. It presents a security-header score, detected values, missing-header recommendations, scan activity, and an exportable JSON report.

## Features

- Dark, neon-accent desktop GUI built with Python Tkinter
- Website URL validation and HTTP/HTTPS support
- Passive HTTP GET request with redirect handling and timeout
- Checks nine response headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Opener-Policy
  - Cross-Origin-Resource-Policy
  - Cross-Origin-Embedder-Policy
- Score out of 100, present/missing counts, and HTTP status
- Per-header explanations and recommendations included in JSON export
- Background scanning thread so the GUI remains responsive

## Requirements

- Python 3.9+
- `requests`

Tkinter is included with most standard Python installations. On some Linux distributions it may need to be installed separately (for example, `python3-tk`).

## Run on Windows (double-click)

1. Install Python 3.9+ and enable **Add Python to PATH** during installation.
2. Double-click `START_SHIELDX.bat`.
3. The launcher installs the required package and opens the GUI.

## Run locally from a terminal

```bash
git clone https://github.com/YOUR-USERNAME/SHIELDX.git
cd SHIELDX
python -m pip install -r requirements.txt
python main.py
```

Enter a website URL (for example, `https://example.com`) and select **SCAN WEBSITE**. Use **EXPORT JSON REPORT** to save the findings.

## How the score works

Each of the nine headers has a configured weight. If a header is present with a non-empty value, its weight is added to the score. The weights total 100. This is a simple presence-based indicator, not a validation of whether the header's value is optimally configured.

## Project structure

```text
SHIELDX/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

## Important limitations

- SHIELDX performs passive response-header inspection only. It does not exploit vulnerabilities, brute-force, crawl a website, or perform a penetration test.
- A present header is not automatically a correctly configured header. Values require context-specific review.
- Some headers are optional or only relevant to particular applications. A missing header is a review recommendation, not proof of a vulnerability.
- The score is a learning/triage aid and is not a formal risk rating or compliance result.
- Only scan websites you own or have explicit permission to assess.

## Future improvements

- Validate header directives and values, not just presence
- HTML/PDF report generation
- Historical scan comparison
- Customizable header profiles
- Unit tests and CI workflow

## Author

**Om Mane**  
Cybersecurity Learner | Python | Web Security

---

Educational project for defensive security learning and portfolio demonstration.
