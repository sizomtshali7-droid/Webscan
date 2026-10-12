# Webscan

A small Python tool that checks a website and its API for common weaknesses. It comes with a practice website that is weak on purpose, so you can test the tool safely.

> **Safety first:** only scan websites you own or have written permission to test. Webscan refuses any website that is not on your own computer unless you confirm permission.

## What it does

Webscan runs 16 checks in four groups and then writes a report that explains each failed check and how to fix it.

| Group | What it looks at |
|---|---|
| Settings and headers | Five safety settings sent by the website, and whether the server reveals its version |
| Cookies | Does each cookie have the HttpOnly, Secure and SameSite protections? |
| Access | Can an order be read without logging in? Can one user read another user's order? Can a normal user open the admin page? Does the admin page need a login? |
| Responses | Do login errors reveal which users exist? Do error pages show internal details? Do replies contain passwords or secrets? |

## Results at a glance

| Practice website | Passed | Failed |
|---|---|---|
| Weak version | 1 | 15 |
| Fixed version | 16 | 0 |

This shows the tool can tell the weak site from the fixed one. See [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md) for every check and the screenshots.

![Weak scan](screenshots/08-weak-scan-part1-summary-and-headers.png)
![Fixed scan](screenshots/16-fixed-scan-part1-summary-headers-cookies.png)

## Requirements

- Python 3.9 or newer (tested on Python 3.14.8 on Windows 10 and Python 3.12 on Linux)
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

Windows (Command Prompt or PowerShell):

```
python -m venv .venv
.venv\Scripts\activate
```

You need to run the activate line again in every new terminal window. When it works, the prompt starts with `(.venv)`.

**3. Install the packages**

```bash
python -m pip install -r requirements.txt
```

Using `python -m pip` makes sure the packages go to the same Python that runs Webscan.

**4. Check that it works**

```bash
python webscan.py --help
```

## Usage

### Quick demo (easiest)

Starts the practice website, scans the weak version, then the fixed version, and saves both reports in a `reports` folder:

```bash
python run_demo.py
```

### Step by step

**1. Start the practice website** (open a terminal and leave it running)

```bash
python practice_app.py --mode weak --port 5000
```

Use `--mode fixed` to run the fixed version instead.

**2. Scan it** (open a second terminal and activate the virtual environment there too)

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

## Troubleshooting (Windows)

These are problems that came up while building this project. More detail is in [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md).

| Problem | Fix |
|---|---|
| `'pip' is not recognized` | Use `python -m pip install -r requirements.txt`. If `python` is not recognised either, install Python from python.org with **Add python.exe to PATH** ticked, then open a new terminal. |
| The Python installer will not run on an older Windows 10 | Download a classic Windows installer (.exe) from the python.org Windows downloads page instead of the default download. |
| `ModuleNotFoundError: No module named 'requests'` | `pip` and `python` are using different installs. Activate the virtual environment, then run `python -m pip install -r requirements.txt`. |
| PowerShell will not run the activate script | Use Command Prompt (`cmd`) instead. |
| Port 5000 is already in use | Add `--port 5100` to the practice website command, and use the same port in the scan address. |
| Connection error when scanning | The practice website is not running. Start it in the first terminal and leave it open. |

## Project files

| File | Purpose |
|---|---|
| `webscan.py` | The scanner: runs the 16 checks and writes the report |
| `practice_app.py` | The practice website, with a weak and a fixed version |
| `run_demo.py` | Runs the whole demo in one command |
| `requirements.txt` | Python packages needed |
| `DESIGN.md` | Design document: architecture, the 16 checks, weak versus fixed |
| `docs/TEST_RESULTS.md` | Test results with screenshots |
| `docs/DEVELOPMENT_LOG.md` | Problems faced during setup and how they were fixed |
| `reports/` | Saved reports from the demo |
| `screenshots/` | Evidence screenshots |
| `LICENSE` | MIT licence |

## Known limits

- It checks a short list of well-known weaknesses and does not try to break in.
- It supports one login style (a JSON login that sets a session cookie).
- It checks that headers are present, not that their values are strong.
- It has only been tested on the included practice website.
- A passing report does **not** mean a website is fully secure.

## Other practice targets

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and [OWASP crAPI](https://owasp.org/www-project-crapi/) are well-known practice targets. Webscan has **not** been tested on them. Their login and page paths are different, and they may use login styles Webscan does not support yet, so using them would need the path options above and possibly code changes.

## Licence

Released under the MIT Licence. See [LICENSE](LICENSE).
