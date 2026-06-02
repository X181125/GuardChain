import subprocess
from setuptools import setup
from setuptools.command.install import install


subprocess.run(["echo", "simulated setup-time action"])


class CustomInstall(install):
    def run(self):
        subprocess.run(["echo", "simulated custom install action"])
        super().run()


setup(
    name="setup-time-malicious-like-pkg",
    version="0.1.0",
    packages=["setup_time_malicious_like_pkg"],
    cmdclass={"install": CustomInstall},
)
