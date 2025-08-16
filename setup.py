from setuptools import setup, find_packages

setup(
    name='adcsreaper',
    version='1.0.0',
    description='ADCS misconfiguration detection & exploitation',
    author='G0urmetD',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        "ldap3",
    ],
    entry_points={
        'console_scripts': [
            'adcsreaper=adcsreaper.adcsreaper:main',
        ],
    },
)
