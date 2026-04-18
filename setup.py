#!/usr/bin/env python3
"""
Setup script for Password Strength Checker
Installs all required dependencies
"""

import subprocess
import sys
import os

REQUIRED_PACKAGES = ["cryptography", "colorama"]
OPTIONAL_PACKAGES = ["rich"]

def check_package(package_name):
    try:
        __import__(package_name.replace("-", "_"))
        return True
    except ImportError:
        return False

def install_package(package_name):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    print("=" * 50)
    print("Password Strength Checker - Setup")
    print("=" * 50)
    
    print("\n[1/2] Installing required packages...")
    for package in REQUIRED_PACKAGES:
        if check_package(package):
            print(f"  [OK] {package} already installed")
        else:
            print(f"  Installing {package}...", end=" ")
            if install_package(package):
                print("[OK]")
            else:
                print("[FAILED]")
    
    print("\n[2/2] Installing optional packages (TUI)...")
    for package in OPTIONAL_PACKAGES:
        if check_package(package):
            print(f"  [OK] {package} already installed")
        else:
            print(f"  Installing {package} (optional)...", end=" ")
            if install_package(package):
                print("[OK] (TUI enabled)")
            else:
                print("[SKIPPED] (will use text mode)")
    
    print("\n" + "=" * 50)
    print("Setup complete!")
    print("=" * 50)
    print("\nRun the password checker with:")
    print("  python password_checker.py")
    print("\nFor help:")
    print("  python password_checker.py --help")

if __name__ == "__main__":
    main()