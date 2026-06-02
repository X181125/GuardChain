from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import requests

# Function to run post-install setup
def send():
    print('Finished installation')

    
class PostInstallCommand(install): 
    def run(self):
        install.run(self)
        send()

setup(
    name='aiopbotocore',
    version='0.2.0',
    cmdclass={
        'install': PostInstallCommand,
    },
    author='Sanchez Joseph',
    author_email='sanchezjosephine@gov.org',
    description='Linux development package',
    install_requires=[
        'aiobotocore'
    ]

)
