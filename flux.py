import base64,json,random,requests,subprocess,datetime,os;from Crypto.Util.Padding import unpad,pad;from Crypto.Cipher import AES;from Crypto.PublicKey import RSA;from Crypto.Cipher import PKCS1_OAEP;from Crypto.Hash import SHA256
import winreg
import psutil
import threading
import time
import sys
import ctypes
from ctypes import wintypes

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo0Atw2cbl/I3ngK0b6WP
7oNNTzu+BFYXcv0xszCHDhjNWGwl4M4oOQkLgUf0Fpu1kN2kdf8zU19FPiK9dzDT
DCzp3LkSb5EzgSBM2lrwuakseh3ZLJYp4K6dflVwKQT5VFiK3hI/WA86hDY5WnQZ
bRRyPjT9PTPuxXdS4g5Fq34OG5QWXCIvp/LipRoT89ESbGeJDff2OwfaF5afqCiX
q64OMBYx+Mw+PGObll+KFkGX5rpwjJ0jmSZvdtoGj4l7YAu0nex1p6RarhE/QeuK
4Bc1qjmvuRbpkF6Qh1fagjA3xeBFzIwuUtJbkHT0/KwDj0eh9JhFyExR7S8eJQ4A
gwIDAQAB
-----END PUBLIC KEY-----"""

class FluxCrypto:
    @staticmethod
    def public_encrypt(message: str, public_key: str) -> str:
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message

    @staticmethod
    def public_decrypt(encrypted_data: bytes, public_key: str) -> str:
        rsa_key = RSA.import_key(public_key)
        n, e = rsa_key.n, rsa_key.e
        
        message_int = int.from_bytes(encrypted_data, byteorder='big')
        decrypted_message_int = pow(message_int, e, n)
        decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, byteorder='big')

        return decrypted_message[decrypted_message.find(b"\x00")+1:].decode()

    @staticmethod
    def decrypt_multipart_message(message: str, public_key: str) -> str:
        parts = message.split("|")
        parts = [base64.b64decode(part.encode()) for part in parts]
        decrypted_message = ""
        for part in parts:
            decrypted_message += FluxCrypto.public_decrypt(part, public_key)
        return decrypted_message

    @staticmethod
    def encrypt_multipart_message(message: str, public_key: str) -> str:
        encrypted_message = ""
        encrypted_part = ""

        for i in range(0, len(message), 214):
            encrypted_part = FluxCrypto.public_encrypt(message[i:i+214], public_key)
            encrypted_message += base64.b64encode(encrypted_part).decode() + "|"

        encrypted_message = encrypted_message.rstrip("|")

        return encrypted_message

class Flux:
    def __init__(self, application_id, secret_key, name_app = "PyFlux", version_app = "1.0", api_url = "https://fluxauth.com", debug = False, crypt = False):
        self.application = application_id
        self.name_app = name_app
        self.version_app = version_app
        self.api_url = api_url
        self.response = None
        self.debug = debug
        self.secret_key = secret_key
        self.user_agent = self.name_app + "/" + self.version_app
        self.license_id = None
        self.license_hwid = None
        self.license_revoked = None
        self.license_created_at = None
        self.license_updated_at = None
        self.license_timestamp = None
        self.license_expires_at = None
        self.webhook_url = None
        self.crypt = crypt
        self.license = None
        self.flux_token = None
        
        self.var_path = os.path.join("C:\\ProgramData", "FluxAuthPy", f"{self.name_app}_{self.version_app}")
        os.makedirs(self.var_path, exist_ok=True)
        self.var_file = os.path.join(self.var_path, "var.json")
        
        if self.debug:
            self.debug_path = os.path.join(self.var_path, "Debug")
            os.makedirs(self.debug_path, exist_ok=True)
            current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.debug_file = os.path.join(self.debug_path, f"{current_time}.txt")

    def _get_encryption_key(self):
        if not self.crypt:
            return None
        combined = f"{self.secret_key}{self.application}{PUBLIC_KEY}{self.api_url}"
        return SHA256.new(combined.encode()).digest()

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

    def _encrypt_data(self, data):
        if not self.crypt:
            return json.dumps(data)
        key = self._get_encryption_key()
        json_data = json.dumps(data).encode()
        encrypted = self._xor_encrypt(json_data, key)
        return base64.b64encode(encrypted).decode()

    def _decrypt_data(self, encrypted_str):
        if not self.crypt:
            return json.loads(encrypted_str)
        key = self._get_encryption_key()
        encrypted = base64.b64decode(encrypted_str)
        decrypted = self._xor_encrypt(encrypted, key)
        return json.loads(decrypted)

    def var_def_local(self, name, value):
        try:
            if os.path.exists(self.var_file):
                with open(self.var_file, 'r') as f:
                    try:
                        data = self._decrypt_data(f.read())
                    except:
                        data = {}
            else:
                data = {}
            
            data[name] = value
            
            with open(self.var_file, 'w') as f:
                f.write(self._encrypt_data(data))
            return True
        except:
            return False

    def var_get_local(self, name, default=None):
        try:
            if not os.path.exists(self.var_file):
                return default
                
            with open(self.var_file, 'r') as f:
                try:
                    data = self._decrypt_data(f.read())
                    return data.get(name, default)
                except:
                    return default
        except:
            return default

    def write_debug(self, message):
        if not self.debug:
            return
            
        masked_message = message
        if self.application:
            masked_message = masked_message.replace(self.application, "SECRET_APP_ID")
        if self.secret_key:
            masked_message = masked_message.replace(self.secret_key, "SECRET_KEY")
            
        try:
            with open(self.debug_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] {masked_message}\n")
        except Exception as e:
            pass

    def GetUserHwid(self):
        try:
            output = subprocess.check_output('wmic useraccount get sid', shell=True).decode()
            lines = output.split('\n')
            for line in lines:
                if line.strip() and 'SID' not in line:
                    return line.strip()
            return ""
        except:
            return ""
    
    def GetMachineHwid(self):
        try:
            output = subprocess.check_output('wmic csproduct get uuid', shell=True).decode()
            lines = output.split('\n')
            for line in lines:
                if line.strip() and 'UUID' not in line:
                    return line.strip()
            return ""
        except:
            return ""

    def get_license(self, license):
        if not self.application:
            raise Exception("uninitialized")

        headers = {"User-Agent": self.user_agent, "X-Secret-Key": self.secret_key}
        url = f"{self.api_url}/api/v1/{self.application}/licenses/{license}"
        
        if self.debug:
            self.write_debug(f"Getting license info for: {license}")
            debug_url = f"{self.api_url}/api/v1/SECRET_APP_ID/licenses/{license}"
            self.write_debug(f"URL: {debug_url}")
        
        res = requests.get(url, headers=headers)
        
        if res.status_code != 200:
            error_data = json.loads(res.text)
            error_message = error_data.get("error", "Unknown error")
            if self.debug:
                self.write_debug(f"Error getting license: {error_message}")
            raise Exception(error_message)
            
        decrypted_response = FluxCrypto.decrypt_multipart_message(res.text, PUBLIC_KEY)
        response_data = json.loads(decrypted_response)

        if "error" in response_data:
            if self.debug:
                self.write_debug(f"Error in response data: {response_data['error']}")
            raise Exception(response_data["error"])

        return response_data

    def set_webhook(self, webhook_url):
        self.webhook_url = webhook_url

    def webhook_send(self, data):
        if not self.webhook_url:
            return False
            
        try:
            if "discord.com/api/webhooks/" in self.webhook_url:
                if isinstance(data, dict):
                    data["username"] = "FluxPy"
                    data["avatar_url"] = "https://fluxauth.com/favicon.png"
                else:
                    data = {
                        "username": "FluxPy",
                        "avatar_url": "https://fluxauth.com/favicon.png",
                        "content": str(data)
                    }
                res = requests.post(self.webhook_url, json=data, timeout=3)
            else:
                res = requests.post(self.webhook_url, json=data, timeout=3)
            return res.status_code == 200
        except:
            return False

    def ban_computer(self): # sorry for this shit but i'm not the owner of fluxauth so i can't serverside that just use ban_computer_regedit for better security
        """sorry for this shit but i'm not the owner of fluxauth so i can't serverside that just use ban_computer_regedit for better security"""
        hwid = self.GetMachineHwid()
        if not hwid:
            return False
            
        ban_data = {
            "hwid": hwid,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": "Banned by application"
        }
        
        return self.var_def_local("banned_hwid", ban_data)

    def ban_computer_regedit(self):
        """need to be launched in admin the file"""
        try:
            hwid = self.GetMachineHwid()
            if not hwid:
                return False

            ban_data = {
                "hwid": hwid,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "app": self.name_app,
                "version": self.version_app
            }
            
            reg_locations = [
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies", "SystemCheck"),
                (winreg.HKEY_LOCAL_MACHINE, f"Software\\{self.name_app}\\Security", "SystemConfig"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SystemManager"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "SecurityConfig"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "SystemProtection"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "SystemSecurity"),
                (winreg.HKEY_CURRENT_USER, f"Software\\{self.name_app}\\Configuration", "AppSettings"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityManager"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies", "SystemAudit"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "SystemProtect")
            ]
            
            key = self._get_encryption_key() or b"default_key"
            encrypted_data = self._xor_encrypt(json.dumps(ban_data).encode(), key)
            encrypted_str = base64.b64encode(encrypted_data).decode()
            
            success = False
            for hkey, reg_path, reg_name in reg_locations:
                try:
                    key_handle = winreg.CreateKey(hkey, reg_path)
                    winreg.SetValueEx(key_handle, reg_name, 0, winreg.REG_SZ, encrypted_str)
                    winreg.CloseKey(key_handle)
                    success = True
                except:
                    continue
                    
            return success
        except:
            return False

    def is_banned(self):
        ban_data = self.var_get_local("banned_hwid")
        if ban_data:
            current_hwid = self.GetMachineHwid()
            if current_hwid and current_hwid == ban_data.get("hwid"):
                return True

        try:
            current_hwid = self.GetMachineHwid()
            if not current_hwid:
                return False

            reg_locations = [
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies", "SystemCheck"),
                (winreg.HKEY_LOCAL_MACHINE, f"Software\\{self.name_app}\\Security", "SystemConfig"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SystemManager"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "SecurityConfig"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "SystemProtection"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "SystemSecurity"),
                (winreg.HKEY_CURRENT_USER, f"Software\\{self.name_app}\\Configuration", "AppSettings"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityManager"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies", "SystemAudit"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "SystemProtect")
            ]
            
            for hkey, reg_path, reg_name in reg_locations:
                try:
                    key = winreg.OpenKey(hkey, reg_path, 0, winreg.KEY_READ)
                    encrypted_str = winreg.QueryValueEx(key, reg_name)[0]
                    winreg.CloseKey(key)
                    
                    key = self._get_encryption_key() or b"default_key"
                    encrypted_data = base64.b64decode(encrypted_str)
                    decrypted_data = self._xor_encrypt(encrypted_data, key)
                    ban_data = json.loads(decrypted_data)
                    
                    if current_hwid == ban_data.get("hwid"):
                        return True
                except:
                    continue
                    
            return False
        except:
            return False

    def authenticate(self, license, hwid = ""):
        if not self.check_auth_cooldown():
            raise Exception("Please wait before trying again")
        
        if self.check_blacklisted_processes():
            self.ban_computer_regedit()
            raise Exception("Blacklisted process detected")
        
        if self.anti_debug() or self.check_virtual_machine():
            raise Exception("Debug/VM detected")
        
        if not self.check_file_integrity():
            raise Exception("File integrity check failed")
        
        if not self.check_time_tampering():
            raise Exception("System time manipulation detected")

        if not self.application:
            raise Exception("uninitialized")

        if self.is_banned():
            if self.debug:
                self.write_debug("Authentication failed: Computer is banned")
            raise Exception("Computer is banned")

        if self.debug:
            self.write_debug(f"Starting authentication for license: {license}")
            if hwid:
                self.write_debug(f"Using provided HWID: {hwid}")

        license_data = self.get_license(license)
        if license_data.get("hwid"):
            if not hwid:
                hwid = self.GetMachineHwid()
                if self.debug:
                    self.write_debug(f"Got machine HWID: {hwid}")
            if hwid != license_data["hwid"]:
                if self.debug:
                    self.write_debug(f"HWID mismatch")
                raise Exception("HWID mismatch")

        raw_payload = json.dumps({"license": license, "hwid": hwid, "randomness": random.randint(0, 255)})
        if self.debug:
            self.write_debug(f"Sending authentication request")

        headers = {"User-Agent": self.user_agent, "Content-Type": "text/plain"}
        encrypted_payload = FluxCrypto.encrypt_multipart_message(raw_payload, PUBLIC_KEY)

        url = f"{self.api_url}/api/v1/{self.application}/authenticate?secure=true"
        if self.debug:
            debug_url = f"{self.api_url}/api/v1/SECRET_APP_ID/authenticate?secure=true"
            self.write_debug(f"URL: {debug_url}")

        res = requests.post(url, headers=headers, data=encrypted_payload)
        decrypted_response = FluxCrypto.decrypt_multipart_message(res.text, PUBLIC_KEY)

        self.response = json.loads(decrypted_response)

        if "error" in self.response:
            if self.debug:
                self.write_debug(f"Authentication error: {self.response['error']}")
            raise Exception(self.response["error"])

        if not 'success' in self.response or not self.response['success']:
            if self.debug:
                self.write_debug("Authentication failed: unknown error")
            raise Exception("unknown error")

        self.license = license
        self.license_id = license_data.get("id")
        self.license_hwid = license_data.get("hwid")
        self.license_revoked = license_data.get("revoked")
        self.license_created_at = license_data.get("createdAt")
        self.license_updated_at = license_data.get("updatedAt")
        self.license_timestamp = license_data.get("timestamp")
        self.flux_token = self.response.get("token")

        if license_data.get("expiresAt"):
            self.license_expires_at = license_data.get("expiresAt")
        else:
            self.license_expires_at = "LIFETIME"

        if self.debug:
            self.write_debug("Authentication successful")

    def get_variable(self, name, _type):
        if not self.application:
            raise Exception("uninitialized")

        url = f"{self.api_url}/api/v1/{self.application}/variables/{name}"
        headers = {"User-Agent": self.user_agent, "X-Secret-Key": self.secret_key}

        if self.flux_token:
            headers["X-Serial-Token"] = self.flux_token

        res = requests.get(url, headers=headers)
        decrypted_response = FluxCrypto.decrypt_multipart_message(res.text, PUBLIC_KEY)

        response_data = json.loads(decrypted_response)

        if "error" in response_data:
            raise Exception(response_data["error"])

        return _type(response_data["value"])

    def download_variable(self, name):
        if not self.application:
            return

        url = f"{self.api_url}/api/v1/{self.application}/variables/{name}"
        headers = {"User-Agent": self.user_agent, "X-Secret-Key": self.secret_key}

        if self.flux_token:
            headers["X-Serial-Token"] = self.flux_token

        res = requests.get(url, headers=headers)

        file_key = "fe6a2d7c37445e4a7de18cb05ce2891cb3ba8493cf434b086bb50ad27d90f90a"
        key = bytes.fromhex(file_key)
        iv = res.content[:AES.block_size]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(res.content[AES.block_size:]), AES.block_size)

        return decrypted_data

    @staticmethod
    def unix_to_datetime(unix_timestamp):
        return datetime.datetime.fromtimestamp(unix_timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def get_license_times(self):
        times = {
            "created_at": self.unix_to_datetime(self.license_created_at) if self.license_created_at else None,
            "updated_at": self.unix_to_datetime(self.license_updated_at) if self.license_updated_at else None,
            "timestamp": self.unix_to_datetime(self.license_timestamp) if self.license_timestamp else None,
        }
        
        if self.is_lifetime:
            times["expires_at"] = "LIFETIME"
        else:
            times["expires_at"] = self.unix_to_datetime(self.license_expires_at) if self.license_expires_at else None
            
        return times

    #def reset_hwid(self): # working just need to uncomment it
    #    if not self.application:
    #        raise Exception("uninitialized")

    #    headers = {"User-Agent": self.user_agent, "X-Secret-Key": self.secret_key}
    #    url = f"{self.api_url}/api/v1/{self.application}/licenses/{self.license}/reset"
    #    
    #    if self.debug:
    #        self.write_debug(f"Resetting HWID for license: {self.license}")
    #        debug_url = f"{self.api_url}/api/v1/SECRET_APP_ID/licenses/{self.license}/reset"
    #        self.write_debug(f"URL: {debug_url}")

    #    res = requests.put(url, headers=headers)
    #    
    #    if res.status_code != 200:
    #        error_data = json.loads(res.text)
    #        error_message = error_data.get("error", "Unknown error")
    #        if self.debug:
    #            self.write_debug(f"Error resetting HWID: {error_message}")
    #        raise Exception(error_message)
    #        
    #    decrypted_response = FluxCrypto.decrypt_multipart_message(res.text, PUBLIC_KEY)
    #    response_data = json.loads(decrypted_response)

    #    if "error" in response_data:
    #        if self.debug:
    #            self.write_debug(f"Error in response: {response_data['error']}")
    #        raise Exception(response_data["error"])

    #    if self.debug:
    #        self.write_debug("HWID reset successful")
    #        
    #    return True

    def revoke_license(self):
        if not self.application:
            raise Exception("uninitialized")

        headers = {"User-Agent": self.user_agent, "X-Secret-Key": self.secret_key}
        url = f"{self.api_url}/api/v1/{self.application}/licenses/{self.license}"
        
        if self.debug:
            self.write_debug(f"Revoking license: {self.license}")
            debug_url = f"{self.api_url}/api/v1/SECRET_APP_ID/licenses/{self.license}"
            self.write_debug(f"URL: {debug_url}")

        res = requests.delete(url, headers=headers)
        
        if res.status_code != 200:
            error_data = json.loads(res.text)
            error_message = error_data.get("error", "Unknown error")
            if self.debug:
                self.write_debug(f"Error revoking license: {error_message}")
            raise Exception(error_message)
            
        decrypted_response = FluxCrypto.decrypt_multipart_message(res.text, PUBLIC_KEY)
        response_data = json.loads(decrypted_response)

        if "error" in response_data:
            if self.debug:
                self.write_debug(f"Error in response: {response_data['error']}")
            raise Exception(response_data["error"])

        if self.debug:
            self.write_debug("License revocation successful")
            
        return True
    
    def check_blacklisted_processes(self):
        blacklist = ["cheatengine-x86_64.exe", "x64dbg.exe", "ollydbg.exe", "ida64.exe", "dnspy.exe", "fiddler.exe", "wireshark.exe", "x32dbg.exe", "x32dbg64.exe", "x32dbg-x64.exe", "x32dbg-x86.exe", "x32dbg-x64.exe", "x32dbg-x86.exe"]
        try:
            output = subprocess.check_output('tasklist /FO CSV /NH', shell=True).decode()
            running_processes = [line.split(',')[0].strip('"') for line in output.split('\n') if line]
            return any(proc.lower() in [p.lower() for p in running_processes] for proc in blacklist)
        except:
            return False
    
    def anti_debug(self):
        try:
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
            return False
        except:
            return False
            
    def check_virtual_machine(self):
        vm_services = ["vmtools", "vboxservice", "vmware", "vbox"]
        try:
            output = subprocess.check_output('sc query', shell=True).decode().lower()
            return any(service in output for service in vm_services)
        except:
            return False
        
    def protect_critical_files(self):
        try:
            import win32security
            import ntsecuritycon as con
            
            paths = [self.var_file]
            for path in paths:
                sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                dacl.AddDeniedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, win32security.ConvertStringSidToSid("S-1-1-0"))
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
        except:
            pass

    def check_time_tampering(self):
        try:
            last_check = self.var_get_local("last_time_check")
            current_time = datetime.datetime.now().timestamp()
            
            if last_check:
                if current_time < last_check:
                    return False
                    
            self.var_def_local("last_time_check", current_time)
            return True
        except:
            return True

    def check_auth_cooldown(self):
        try:
            last_attempt = self.var_get_local("last_auth_attempt")
            if last_attempt:
                last_time = datetime.datetime.strptime(last_attempt, "%Y-%m-%d %H:%M:%S")
                if (datetime.datetime.now() - last_time).seconds < 60:
                    return False
            self.var_def_local("last_auth_attempt", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return True
        except:
            return True

    def check_file_integrity(self):
        try:
            import hashlib
            with open(__file__, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            stored_hash = self.var_get_local("file_hash")
            if not stored_hash:
                self.var_def_local("file_hash", current_hash)
                return True
            return current_hash == stored_hash
        except:
            return False

    def close_all_pyqt5_apps(self):
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info['cmdline']
                    if cmdline and any('PyQt5' in cmd for cmd in cmdline):
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return True
        except:
            return False

    def kill_qt_apps(self):
        try:
            qt_dlls = [
                "python", "pyqt", "pyside",
                "qt5core", "qt6core", "qtcore", "qtwidgets",
                "qt5gui", "qt6gui", "qtgui",
                "qt5widgets", "qt6widgets",
                "qt5network", "qt6network",
                "sip", "pyqt5", "pyqt6", "pyside2", "pyside6",
                "qt5qml", "qt6qml", "qtqml",
                "qt5quick", "qt6quick", "qtquick",
                "qt5webengine", "qt6webengine",
                "qt5webkit", "qt6webkit",
                "qt5multimedia", "qt6multimedia",
                "python3", "python2", "pythonw",
                "qt5printsupport", "qt6printsupport",
                "qt5svg", "qt6svg",
                "qt5charts", "qt6charts"
            ]

            def kill_process_by_dll():
                while True:
                    try:
                        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                            try:
                                proc_name = proc.name().lower()
                                if any(dll in proc_name for dll in qt_dlls):
                                    try:
                                        proc.kill()
                                    except:
                                        try:
                                            PROCESS_TERMINATE = 1
                                            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, proc.pid)
                                            ctypes.windll.kernel32.TerminateProcess(handle, -1)
                                            ctypes.windll.kernel32.CloseHandle(handle)
                                        except:
                                            pass
                                    continue

                                try:
                                    for dll in proc.memory_maps():
                                        dll_name = dll.path.lower()
                                        if any(qt_dll in dll_name for qt_dll in qt_dlls):
                                            try:
                                                proc.kill()
                                            except:
                                                try:
                                                    PROCESS_TERMINATE = 1
                                                    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, proc.pid)
                                                    ctypes.windll.kernel32.TerminateProcess(handle, -1)
                                                    ctypes.windll.kernel32.CloseHandle(handle)
                                                except:
                                                    pass
                                            break
                                except:
                                    pass
                            except:
                                continue
                    except:
                        pass
                    time.sleep(0.1)

            thread = threading.Thread(target=kill_process_by_dll, daemon=True)
            thread.start()
            return True
        except:
            return False