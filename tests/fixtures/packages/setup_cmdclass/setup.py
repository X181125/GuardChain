from setuptools import setup
from setuptools.command.install import install
import os


class CustomInstall(install):
    def run(self):
        runner = os.system
        runner("echo test")


setup(name="fixture-setup-cmdclass", cmdclass={"install": CustomInstall})
