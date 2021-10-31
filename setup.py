#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="Spartancoin",
    version="0.1.0",
    description="Spartancoin Cryptocurrency",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
)
