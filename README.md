# Webscan

A small Python tool that checks a website and its API for common weaknesses. It comes with a practice website that is weak on purpose, so you can test the tool safely.

> **Safety first:** only scan websites you own or have written permission to test. Webscan refuses any website that is not on your own computer unless you confirm permission.

## What it does

Webscan runs 16 checks in four groups and then writes a report that explains each failed check and how to fix it.

| Group | What it looks at |
|---|---|
| Settings and headers | Five safety settings sent by the website, and whether the server reveals its version |
| Access | Can an order be read without logging in? Can one user read another user's order? Can a normal user open the admin page? Does the admin page need a login? |
| Responses | Do login errors reveal which users exist? Do error pages show internal details? Do replies contain passwords or secrets? |
| Cookies | Does each cookie have the HttpOnly, Secure and SameSite protections? |

**Expected result on the practice website:** the weak version fails 15 of the 16 checks, and the fixed version passes all 16. This shows the tool can tell the difference.

## Requirements

- Python 3.9 or newer
- Git
- Internet access for installing (the tool itself scans locally by default)

Python packages (listed in `requirements.txt`): `requests` and `Flask`.

## Installation

**1. Get the code**

```bash
git clone https://github.com/sizomtshali7-droid/Webscan.git
cd Webscan
```

**2. Create a virtual environment (recommended)**

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\activate
```

**3. Install the packages**

```bash
pip install -r requirements.txt
```

**4. Check that it works**

```bash
python webscan.py --help
```

## Usage

**1. Start the practice website** (open a terminal and leave it running)

```bash
python practice_app.py --mode weak --port 5000
```

Use `--mode fixed` to run the fixed version instead.

**2. Scan it** (open a second terminal)

```bash
python webscan.py http://127.0.0.1:5000
```

**3. Read the report.** It is printed on screen and saved to `webscan_report.md`. Each failed check shows what was seen and how to fix it.

**4. Try the fixed version.** Stop the practice website (Ctrl+C), start it again with `--mode fixed`, and scan again. All 16 checks should pass.

### Options

| Option | Meaning | Default |
|---|---|---|
| `--i-have-permission` | Confirm you may test a website that is not on your computer | off |
| `--user1 name:password` | A normal (non-admin) user to log in as | `alice:alice-pass` |
| `--order1 ID` / `--order2 ID` | An order that belongs to that user / to a different user | `1` / `2` |
| `--login-path`, `--orders-path`, `--admin-path` | Where those pages live on the website | `/api/login`, `/api/orders`, `/admin` |
| `--report FILE` | Where to save the report | `webscan_report.md` |

Webscan exits with code `0` if every check passes, `1` if any check fails, and `2` if it could not run.

### Scanning a website that is not on your computer

Webscan refuses this by default. Only if you own the website or have permission:

```bash
python webscan.py https://your-own-site.example --i-have-permission
```

## Project files

| File | Purpose |
|---|---|
| `webscan.py` | The scanner: runs the 16 checks and writes the report |
| `practice_app.py` | The practice website, with a weak and a fixed version |
| `requirements.txt` | Python packages needed |
| `LICENSE` | MIT licence |

## Known limits

- It checks a short list of well-known weaknesses and does not try to break in.
- It supports one login style.
- A passing report does **not** mean a website is fully secure.

## More practice targets

If you want more to practise on, see [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and [OWASP crAPI](https://owasp.org/www-project-crapi/).

## Licence

Released under the MIT Licence. See [LICENSE](LICENSE).
