"""This is the setup module for the cyhy-commander project."""
from setuptools import setup, find_packages

setup(
    name="cyhy-commander",
    version="0.0.3",
    author="Mark Feldhousen",
    author_email="mark.feldhousen@cisa.dhs.gov",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "cyhy-commander=cyhy_commander.commander:main",
            "cyhy-nessus-import=cyhy_commander.nessus_import_tool:main",
        ]
    },
    license="LICENSE",
    description="Command and control application for Cyber Hygiene",
    long_description=open("README.md").read(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: Public Domain",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Topic :: Security",
    ],
    python_requires="== 2.7.18",
    install_requires=[
        "cyhy-core @ git+https://github.com/cisagov/cyhy-core@v0.0.2",
        "docopt == 0.6.2",
        "Fabric == 1.15.0",
        "lockfile == 0.12.2",
        "python-daemon == 2.3.0",
    ],
)
