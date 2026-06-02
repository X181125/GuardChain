import os
import subprocess as sp


cmd = os.system
runner = cmd
runner("echo test")
sp.run("echo test", shell=True)
