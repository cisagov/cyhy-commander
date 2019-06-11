from setuptools import setup, find_packages

setup(
    name="cyhy-commander",
    version="0.0.2",
    author="Mark Feldhousen Jr.",
    author_email="mark.feldhousen@hq.dhs.gov",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "cyhy-commander=cyhy_commander.commander:main",
            "cyhy-nessus-import=cyhy_commander.nessus_import_tool:main",
        ]
    },
    # license='LICENSE.txt',
    description="Command and control application for Cyber Hygiene",
    # long_description=open('README.txt').read(),
    install_requires=[
        "cyhy-core >= 0.0.2",
        "Fabric >= 1.8.3, < 2.0.0",
        "docopt >= 0.6.2",
        "python-daemon >= 1.6",
        "lockfile >= 0.9.1",
    ],
)
