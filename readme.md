# System Information Grabber

## Overview

This Python script collects detailed system and user information from a Windows system and sends it to multiple Discord webhooks. It generates reports on IP and location data, browser passwords, tokens, cookies, system events, user accounts, installed programs, network connections, and environment variables.

### Features

- **IP and Location:** Fetches public IP, hostname, local IP, and geolocation data.
- **Browser Data:** Extracts passwords and cookies from Chrome, Firefox, Edge, Opera, Brave, Vivaldi, and UCBrowser.
- **Application Data:** Retrieves Discord tokens and Steam account names.
- **Extra System Info:** Includes Windows Event Logs, `net user` output, and recently opened files.
- **Advanced System Info:** Provides system specifications, installed programs, active network connections (`netstat`), and environment variables.
- **Webhook Splitting:** Sends data to four separate Discord webhooks, with messages split to respect the 2000-character limit.

## Requirements

- **Operating System:** Windows
- **Python Version:** 3.6+
- **Dependencies:**
  - `requests` - For HTTP requests to Discord and IP APIs.
  - `browser_cookie3` - For extracting browser cookies.
  - `pycryptodomex` - For AES decryption of browser passwords.
  - `pywin32` - For Windows-specific functions (e.g., `win32crypt`).
  - `psutil` - For system resource information (CPU, RAM).

Install dependencies using pip:
```bash
pip install requests browser-cookie3 pycryptodomex pywin32 psutil