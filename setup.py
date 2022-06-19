from setuptools import setup, find_packages

setup(
    name = "pcap_virus_scan",
    py_modules=['pcap_virus_scan'],
    packages=find_packages(where='src'),
    package_dir={'':'src'},
)
