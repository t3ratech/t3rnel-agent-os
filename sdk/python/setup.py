from setuptools import setup

setup(
    name="t3rnel",
    version="0.1.0",
    description="Official Python client for the T3rnel Agent OS REST API",
    py_modules=["t3rnel_sdk", "t3rnel_client"],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
