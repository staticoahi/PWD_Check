# -*- coding: utf-8 -*-
"""
This script is an interactive password strength checker.

It checks a user's password against several criteria:
-   If it's found in a list of common passwords fetched from the internet.
-   Minimum length requirements.
-   Presence of uppercase, lowercase, numbers, and special characters.
-   Whether it contains sequential or repeating character patterns.

The script provides feedback and suggestions, including generating a secure
random password if the user's input is too weak.
"""
import urllib.request
import secrets
import string

# --- Helper Functions ---

def generate_secure_password():
    """
    Generates a cryptographically strong 16-character password.
    
    It uses the `secrets` module for secure random number generation.
    The password is guaranteed to contain at least one lowercase letter,
    one uppercase letter, one digit, and one special character.

    Returns:
        str: A securely generated password.
    """
    # Define the character set for the password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        # Generate a 16-character password from the alphabet
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        # Ensure the generated password meets all character type requirements
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
            return password

def get_common_passwords():
    """
    Fetches a list of common passwords from a predefined list of URLs.
    
    It tries URLs in order and uses the first one that works, making the tool
    more resilient if one source is unavailable.

    Returns:
        set: A set of common passwords in lowercase. Returns an empty set if
             no list could be fetched.
    """
    # A list of reliable sources for common password lists
    password_list_urls = [
        "https://gist.githubusercontent.com/cihanmehmet/68abd1a11b3477ebd30eea7ef23183b5/raw/c06ff4cb95e3cc6679d3cd74f24617f498158f9e/password-wordlist.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    ]
    
    print("Attempting to fetch a common password list from known sources...")
    # Iterate through the URLs and try to download the list
    for url in password_list_urls:
        print(f"Trying: {url}")
        try:
            # Try to open the URL with a 5-second timeout
            with urllib.request.urlopen(url, timeout=5) as response:
                # Read the list, decode, strip whitespace, and convert to a lowercase set for fast lookups
                common_passwords = set(line.decode('utf-8').strip().lower() for line in response)
                print("...Success! A common password list has been loaded.")
                return common_passwords
        except urllib.error.URLError as e:
            # Handle network-related errors
            print(f"...Failed: {e.reason}")
        except Exception as e:
            # Handle other potential errors (e.g., timeouts, decoding errors)
            print(f"...Failed with an unexpected error: {e}")

    # This message is shown if the loop completes without returning (i.e., all URLs failed)
    print("\nCould not fetch any common password lists. Proceeding without this check.")
    return set()

def check_password_weaknesses(password):
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

    # Rule 1: Minimum Length
    if len(password) < min_length:
        weaknesses.append(f"Is shorter than the minimum of {min_length} characters.")

    # Rule 2: Character Variety (ensures complexity)
    if not any(c.isupper() for c in password):
        weaknesses.append("Does not contain any uppercase letters.")
    if not any(c.islower() for c in password):
        weaknesses.append("Does not contain any lowercase letters.")
    if not any(c.isdigit() for c in password):
        weaknesses.append("Does not contain any numbers.")
    if not any(c in string.punctuation for c in password):
        weaknesses.append("Does not contain any special characters.")

    # Rule 3: Forbids Sequential Characters (e.g., "abc", "123")
    for i in range(len(password) - 2):
        # Check for sequential letters (case-insensitive)
        if password[i:i+3].isalpha() and ord(password[i].lower()) + 1 == ord(password[i+1].lower()) and ord(password[i+1].lower()) + 1 == ord(password[i+2].lower()):
            weaknesses.append("Contains sequential characters (like 'abc').")
            break
        # Check for sequential numbers
        if password[i:i+3].isdigit() and int(password[i]) + 1 == int(password[i+1]) and int(password[i+1]) + 1 == int(password[i+2]):
            weaknesses.append("Contains sequential numbers (like '123').")
            break
            
    # Rule 4: Forbids Repeating Characters (e.g., "aaa", "111")
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            weaknesses.append("Contains repeating characters (like 'aaa').")
            break
            
    return weaknesses

# --- Main Application Logic ---

def main():
    """Main function to run the interactive password checker."""
    # Step 1: Download the list of common passwords when the script starts.
    common_passwords = get_common_passwords()
    
    attempt_count = 0
    # Step 2: Start the main interactive loop.
    while True:
        password = input("\nEnter your Password (or type 'exit' to quit): ")
        if password.lower() == 'exit':
            break

        # Step 3: Perform the most critical check first: is the password extremely common?
        if password.lower() in common_passwords:
            print("\n--- 💀 WARNING: This is a very common password! 💀 ---")
            print("Your password is on a list of commonly used passwords and is not secure.")
            
            # Immediately suggest a secure alternative.
            new_password = generate_secure_password()
            print(f"\nWe suggest using a stronger, randomly generated password like: {new_password}")
            
            # Ask the user if they want to accept the suggestion.
            while True:
                choice = input("Would you like to accept this password? (yes/no): ").lower()
                if choice in ['yes', 'y']:
                    print(f"\nYour new secure password is: {new_password}")
                    return # Exit the application entirely.
                elif choice in ['no', 'n']:
                    print("Please try entering a different password.")
                    break # Break from this inner loop to let the user try again.
            continue # Continue to the next iteration of the main loop.

        # Step 4: If not a common password, check for other structural weaknesses.
        weaknesses = check_password_weaknesses(password)
        
        # Step 5: Handle the outcome of the weakness check.
        if not weaknesses:
            # Case A: No weaknesses found. The password is strong.
            print("\n--- ✅ Password is valid and appears to be strong. ---")
            break # Exit the main loop, as the goal is achieved.
        else:
            # Case B: Weaknesses were found.
            attempt_count += 1
            print("\n--- ⚠️ Your password could be stronger. Here's why: ---")
            for weakness in weaknesses:
                print(f"- {weakness}")

            # If the user has failed twice, offer more direct help.
            if attempt_count >= 2:
                print("\nYou've tried a couple of times. Still not a strong password.")
                new_password = generate_secure_password()
                print(f"\nWe suggest using a stronger, randomly generated password like: {new_password}")
                while True:
                    choice = input("Would you like to accept this password, or try again yourself? (accept/try): ").lower()
                    if choice in ['accept', 'a']:
                        print(f"\nYour new secure password is: {new_password}")
                        return # Exit the application.
                    elif choice in ['try', 't']:
                        attempt_count = 0 # Reset the counter if they want to try again.
                        break # Break inner loop to let them try again.
            else: 
                # This is the first failed attempt.
                print("\nPlease try another password.")

# This is the standard entry point for a Python script.
# It ensures that the `main()` function is called only when the script is executed directly.
if __name__ == "__main__":
    main()
