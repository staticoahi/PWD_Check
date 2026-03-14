# Password Strength Checker

This is an interactive command-line tool to help you check the strength of your passwords and encourage the use of more secure ones.

## Features

The script checks your password against several security criteria:

- **Common Password Check:** It downloads a list of known common passwords from public sources and warns you if your password is on the list.
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

## Requirements

- **Python 3.x:** The script is written in Python 3.
- **Internet Connection:** An internet connection is required on the first run to download the list of common passwords.

No external libraries need to be installed. The script uses only standard Python libraries.

## How to Use

1. **Open your terminal** (like Command Prompt, PowerShell, or Terminal on macOS/Linux).
2. **Navigate to the directory** where you have saved `password_checker.py`:
    ```sh
    cd path/to/your/folder
    ```
3. **Run the script** using the `python` command:
    ```sh
    python password_checker.py
    ```
4. **Follow the interactive prompts:**
    - The script will first attempt to download the password list.
    - It will then prompt you to enter a password or select an option to check a CSV file.
    - Read the feedback provided. If your password is weak, the script will explain why and ask you to try again or offer a secure alternative.

## Tool Behavior

The goal of this tool is to be an interactive password coach.

- **Immediate Feedback:** You get instant feedback on the structural weaknesses of your password.
- **Strict on Common Passwords:** If your password is on a common list, the tool will strongly warn you and immediately suggest an alternative. This is the most critical check.
- **Interactive Improvement:** For other weaknesses, it gives you a chance to try again and improve. If you still struggle after a couple of tries, it will offer to generate a password for you to provide a clear path forward to better security.

## Exit Option

To exit the program, simply select option `3` when prompted.

