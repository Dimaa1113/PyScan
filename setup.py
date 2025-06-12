from setuptools import setup, find_packages, Extension
from Cython.Build import cythonize
import os

# Define the Cython extension module
# The name "port_scanner.scanner.scanner" should match what's used in port_scanner/scanner/setup.py
# and how it's imported in port_scanner/__init__.py
extensions = [
    Extension(
        "port_scanner.scanner.scanner", # The full import path for the .so file
        [os.path.join("port_scanner", "scanner", "scanner.pyx")],
        # Add any necessary compile/link args here if they are global to this extension
    )
]

setup(
    name="cython-port-scanner-ru", # Renamed for clarity
    version="0.1.0",
    author="Jules (AI Agent)",
    author_email="none@example.com",
    description="Невероятно быстрый полноценный сканнер портов на Cython (на русском)",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="about:blank", # Replace with actual URL if available
    license="MIT", # Or your chosen license
    packages=find_packages(exclude=["tests", "tests.*"]),
    # Include the Cython extension
    ext_modules=cythonize(
        extensions,
        compiler_directives={'language_level': "3"},
        # annotate=True # Useful for debugging Cython code
    ),
    # Define the command-line script
    entry_points={
        "console_scripts": [
            "cython-port-scanner-ru=port_scanner.cli:main",
        ],
    },
    # Specify Python version requirements
    python_requires=">=3.7", # Cython and ipaddress module compatibility
    # Add other dependencies here if any (e.g., if you used external libs beyond standard)
    install_requires=[
        # "cython", # Usually a build dependency, not runtime unless needed explicitly
    ],
    # Build dependencies
    setup_requires=['cython>=0.29', 'setuptools>=42'], # Cython is needed to build
    classifiers=[
        "Development Status :: 3 - Alpha", # Or "4 - Beta", "5 - Production/Stable"
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
    zip_safe=False, # Cython extensions often make zip_safe=False a good idea
)
