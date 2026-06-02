import subprocess
from setuptools import setup


subprocess.run(["python", "--version"])

setup(
    name="malicious-like-pkg",
    version="0.1.0",
    packages=["malicious_like_pkg"],
    install_requires=["requests", "bot-package"],
)
