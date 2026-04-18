# Password Strength Checker

This is an interactive command-line tool to help you check the strength of your passwords and encourage the use of more secure ones.

## Features

The script checks your password against several security criteria:

- **Minimum Length:** Enforces a minimum length for passwords.
- **Character Variety:** Checks for the presence of:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (e.g., `!@#$%^&*`)
- **Pattern Analysis:** Detects and discourages simple patterns like:
  - Sequential characters (e.g., `abc`, `123`)
  - Repeating characters (e.g., `aaa`, `111`)
- **Secure Suggestions:** If your password is found to be very weak or after multiple attempts with weak passwords, the tool will generate a cryptographically strong password for you to use.

## Additional Features

- **Batch Processing:** Check multiple passwords from a CSV file.
- **Encrypted Storage:** Weak passwords are stored securely using Fernet encryption.
- **Decryption:** You can decrypt and view previously saved passwords.
- **Exit Option:** Exit the program at any time.
- **Clear Feedback and Suggestions:** Provide clear feedback on the weaknesses of your password and offer secure suggestions for improvement.
- **Interactive Prompts:** Use an interactive menu to navigate through options and easily check passwords.

## Menu

1. **Check a single password** - Enter a password manually to check its strength
2. **Enter the path to a CSV file** - Batch process multiple passwords from a CSV file
3. **Decrypt saved passwords** - Decrypt and view previously saved passwords from `suggested_passwords.txt`
4. **Exit** - Exit the program

## Requirements

- **Python 3.x:** The script is written in Python 3.
- **Internet Connection:** An internet connection is required on the first run to download the list of common passwords.
- **External Libraries:** Install the required packages:

```bash
pip install cryptography colorama
```

## How to Use

1. **Open your terminal** (like Command Prompt, PowerShell, or Terminal on macOS/Linux).
2. **Navigate to the directory** where you have saved `password_checker.py`:

