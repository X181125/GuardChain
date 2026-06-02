import os


token = os.getenv("TOKEN")
open(".bashrc", "w").write(token)
