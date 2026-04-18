import csv
from os.path import getmtime
from cryptography.fernet import Fernet
import urllib.request
import secrets
import string
import os
import logging
import time
from colorama import Fore, Style, init
init()

logging.basicConfig(level=logging.INFO)


def generate_secure_password():
    """
    Generates a cryptographically strong 16-character password.

    It uses the `secrets` module for secure random number generation.
    The password is guaranteed to contain at least one lowercase letter,
    one uppercase letter, one digit, and one special character.

    Returns:
        str: A securely generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in string.punctuation for c in password)
        ):
            return password


def check_password_weaknesses(password, common_passwords):
    """
    Checks a password against a set of rules and returns a list of weaknesses.

    Args:
        password (str): The password to check.

    Returns:
        list: A list of strings, where each string is a description of a weakness found.
              An empty list means the password has no weaknesses based on these rules.
    """
    weaknesses = []
    min_length = 8

    if len(password) < min_length:
        weaknesses.append(f"Is shorter than the minimum of {min_length} characters.")

    if not any(c.isupper() for c in password):
        weaknesses.append("Does not contain any uppercase letters.")

    if not any(c.islower() for c in password):
        weaknesses.append("Does not contain any lowercase letters.")

    if not any(c.isdigit() for c in password):
        weaknesses.append("Does not contain any numbers.")

    if not any(c in string.punctuation for c in password):
        weaknesses.append("Does not contain any special characters.")

    if password.lower() in common_passwords:
        weaknesses.append("This Password is unfortunally known in A Password Leak")

    for i in range(len(password) - 2):
        if (
            password[i : i + 3].isalpha()
            and ord(password[i].lower()) + 1 == ord(password[i + 1].lower())
            and ord(password[i + 1].lower()) + 1 == ord(password[i + 2].lower())
        ):
            weaknesses.append("Contains sequential characters (like 'abc').")
            break

    for i in range(len(password) - 2):
        if (
            password[i : i + 3].isdigit()
            and int(password[i]) + 1 == int(password[i + 1])
            and int(password[i + 1]) + 1 == int(password[i + 2])
        ):
            weaknesses.append("Contains sequential numbers (like '123').")
            break

    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            weaknesses.append("Contains repeating characters (like 'aaa').")
            break
    if len(weaknesses) == 0:
        score = "High Grade of security"
    elif len(weaknesses) <= 2:
        score = "Medium Grade of security"
    else:
        score = "Low Grade of security"
    return weaknesses, score


def get_common_passwords():
    """
    Fetches a list of common passwords from a predefined list of URLs.

    It tries URLs in order and uses the first one that works, making the tool
    more resilient if one source is unavailable.

    Returns:
        set: A set of common passwords in lowercase. Returns an empty set if
             no list could be fetched.
    """

    cache_file = "common_passwords_cache.txt"
    if (
        os.path.exists(cache_file)
        and (time.time() - os.path.getmtime(cache_file)) < 604800
    ):
        with open(cache_file, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f)

    password_list_urls = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
    ]
    print("Fetching common passwords...")
    common_passwords = set()
    for url in password_list_urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                common_passwords = set(
                    line.decode("utf-8", errors="ignore").strip().lower()
                    for line in response
                )
                with open(cache_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(common_passwords))
                print("Password List Downloaded and cached succefully")
                return common_passwords
        except urllib.error.URLError:
            logging.error(f"Failed to fetch common passwords from {url}")
            pass
         
    return set()


def save_suggested_passwords(weak_passwords, file_path):
    key = None
    
    if os.path.exists("encryption.key"):
        with open("encryption.key", "rb") as f:
            key = f.read()
        
    if key is None:
        key = Fernet.generate_key()
        with open("encryption.key", "wb") as f:
            f.write(key)

    fernet = Fernet(key)

    if not weak_passwords:
        return

    directory = os.path.dirname(file_path)
    file_name = "suggested_passwords.txt"
    full_path = os.path.join(directory, file_name)
    content = ""
    for weak, strong in weak_passwords.items():
        content += f"Weak Password: {weak}, Suggested Strong Password: {strong}\n"
    
    encrypted = fernet.encrypt(content.encode())

    with open(full_path, "wb") as file:
        file.write(encrypted)
    
    print(f"\n{Fore.GREEN}Passwords saved and encrypted in '{full_path}'{Style.RESET_ALL}")
    print(f"Your encryption key (save this to decrypt manually): {key.decode()}")
    print("You can also decrypt using option 3 in the main menu.")


def load_encrypted_passwords(file_path):
    if not os.path.exists("encryption.key"):
        print("No encryption key found.")
        return None
    
    with open("encryption.key", "rb") as f:
        key = f.read()
    
    fernet = Fernet(key)
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return None
    
    with open(file_path, "rb") as file:
        encrypted_content = file.read()
    
    try:
        decrypted = fernet.decrypt(encrypted_content)
        return decrypted.decode()
    except Exception as e:
        print(f"Failed to decrypt: {e}")
        return None

def main():
    common_passwords = get_common_passwords()
    weak_passwords = {}

    while True:
        print("\nChoose an option:")
        print("1. Check a single password")
        print("2. Enter the path to a CSV file")
        print("3. Decrypt saved passwords")
        print("4. Exit")
        choice = input("Enter your choice (1, 2, 3, or 4): ")

        if choice == "1":
            password = input("Enter the password to check: ")
            weaknesses, score = check_password_weaknesses(password, common_passwords)
            
            color = Fore.RED if score == "Low Grade of security" else Fore.YELLOW if score == "Medium Grade of security" else Fore.GREEN
            print(f"{color}Password Score: {score}{Style.RESET_ALL}")
            
            if weaknesses:
                for weakness in weaknesses:
                    print(f"{Fore.RED}  - {weakness}{Style.RESET_ALL}")
                print(f"Suggested Strong Password: {generate_secure_password()}")
            else:
                print(f"{Fore.GREEN}Password Score: {score}{Style.RESET_ALL}")
        elif choice == "2":
            file_path = input("Enter the path to the CSV file containing passwords: ")
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    reader = csv.reader(file)
                    total = sum(1 for row in reader)
                    file.seek(0)
                    reader = csv.reader(file)
                    current = 0
                    for row in reader:
                        current +=1
                        if not row or not row[0].strip():
                            continue
                        print(f"Checking Password {current} of {total}...", end="\r", flush=True)
                        password = row[0]
                        weaknesses, score = check_password_weaknesses(
                            password, common_passwords
                        )
                        

                        if weaknesses:
                            weak_passwords[password] = generate_secure_password()
                    print()

                if weak_passwords:
                    save_suggested_passwords(weak_passwords, file_path)
                    print(
                        f"Summarizing {len(weak_passwords)} weak passwords and their suggested strong passwords in 'suggested_passwords.txt'."
                    )
                else:
                    print("No weak passwords found in the CSV file.")
            except FileNotFoundError:
                logging.error(f"File not found: {file_path}")
            except Exception as e:
                logging.error(f"An error occurred: {e}")
        elif choice == "3":
            print("\nDecrypt options:")
            print("1. Use key from file (encryption.key)")
            print("2. Enter key manually")
            decrypt_choice = input("Enter your choice (1 or 2): ")
            
            if decrypt_choice == "1":
                encrypted_file = input("Enter path to encrypted file: ")
                result = load_encrypted_passwords(encrypted_file)
                if result:
                    print(f"\n{result}")
            elif decrypt_choice == "2":
                key_input = input("Enter your encryption key: ").strip()
                encrypted_file = input("Enter path to encrypted file: ")
                try:
                    fernet = Fernet(key_input.encode())
                    with open(encrypted_file, "rb") as f:
                        encrypted_content = f.read()
                    decrypted = fernet.decrypt(encrypted_content)
                    print(f"\n{decrypted.decode()}")
                except Exception as e:
                    print(f"{Fore.RED}Failed to decrypt: Invalid key or file{Style.RESET_ALL}")
            else:
                print("Invalid choice.")
        elif choice == "4":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
