#!/usr/bin/env python3
"""
Setup script for LEASH (Liveness-Enforced Authorization for Swarm Hierarchies)
"""
 
from setuptools import setup, find_packages
 
setup(
    name="leash",
    version="0.1.0",
    description="Liveness-Enforced Authorization for Swarm Hierarchies",
    author="Research Project",
    license="CC BY-NC-ND 4.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "ecdsa>=0.18.0",
        "bip32utils>=0.3.0",
        "mnemonic>=0.20",
        "pynacl>=1.5.0",
        "matplotlib>=3.7.0",
        "seaborn>=0.12.0",
        "plotly>=5.14.0",
        "networkx>=3.1",
        "rich>=13.0.0",
    ],
    python_requires=">=3.8",
)
