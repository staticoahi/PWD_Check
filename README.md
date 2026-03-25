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
- **Exit Option:** Exit the program at any time.
- **Clear Feedback and Suggestions:** Provide clear feedback on the weaknesses of your password and offer secure suggestions for improvement.
- **Interactive Prompts:** Use an interactive menu to navigate through options and easily check passwords.

## Requirements

- **Python 3.x:** The script is written in Python 3.
- **Internet Connection:** An internet connection is required on the first run to download the list of common passwords.

No external libraries need to be installed. The script uses only standard Python libraries.

## How to Use

1. **Open your terminal** (like Command Prompt, PowerShell, or Terminal on macOS/Linux).
2. **Navigate to the directory** where you have saved `password_checker.py`:

