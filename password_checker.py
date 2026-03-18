import csv
import urllib.request
import secrets
import string
import os
import logging

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

    return weaknesses


def get_common_passwords():
    """
    Fetches a list of common passwords from a predefined list of URLs.

    It tries URLs in order and uses the first one that works, making the tool
    more resilient if one source is unavailable.

    Returns:
        set: A set of common passwords in lowercase. Returns an empty set if
             no list could be fetched.
    """
    password_list_urls = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
    ]

    for url in password_list_urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                common_passwords = set(
                    line.decode("utf-8", errors="ignore").strip().lower()
                    for line in response
                )
                return common_passwords
        except urllib.error.URLError:
            logging.error(f"Failed to fetch common passwords from {url}")
            pass

    return set()


def save_suggested_passwords(weak_passwords, file_path):
    """
    Saves the weak passwords and their suggested strong passwords to a text file.

    Args:
        weak_passwords (dict): A dictionary where keys are weak passwords and values are suggested strong passwords.
        file_path (str): The path to the CSV file where the passwords were checked.
    """
    directory = os.path.dirname(file_path)
    file_name = "suggested_passwords.txt"
    full_path = os.path.join(directory, file_name)

    with open(full_path, "w", encoding="utf-8") as file:
        for weak, strong in weak_passwords.items():
            file.write(f"Weak Password: {weak}, Suggested Strong Password: {strong}\n")


def main():
    common_passwords = get_common_passwords()
    weak_passwords = {}

    while True:
        print("\nChoose an option:")
        print("1. Check a single password")
        print("2. Enter the path to a CSV file")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            password = input("Enter the password to check: ")
            weaknesses = check_password_weaknesses(password, common_passwords)

            if weaknesses:
                print("This password is weak.")
                for weakness in weaknesses:
                    print(f"  - {weakness}")
                print(f"Suggested Strong Password: {generate_secure_password()}")
            else:
                print("This password is strong!")
        elif choice == "2":
            file_path = input("Enter the path to the CSV file containing passwords: ")
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    reader = csv.reader(file)
                    for row in reader:
                        password = row[0]
                        weaknesses = check_password_weaknesses(
                            password, common_passwords
                        )

                        if weaknesses:
                            weak_passwords[password] = generate_secure_password()

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
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
