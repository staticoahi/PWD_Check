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
- **CLI Support:** Use command-line arguments for automation.
- **Clear Feedback and Suggestions:** Provide clear feedback on the weaknesses of your password and offer secure suggestions for improvement.
- **Interactive Prompts:** Use an interactive menu to navigate through options and easily check passwords.

## Menu (Interactive Mode)

1. **Check a single password** - Enter a password manually to check its strength
2. **Enter the path to a CSV file** - Batch process multiple passwords from a CSV file
3. **Decrypt saved passwords** - Decrypt and view previously saved passwords from `suggested_passwords.txt`
4. **Exit** - Exit the program

## Command-Line Options

```bash
python password_checker.py [OPTIONS]
```

| Option | Alias | Description |
|--------|-------|-------------|
| `--check PASSWORD` | `-c` | Check a single password |
| `--file FILE` | `-f` | Check passwords from a CSV file |
| `--column N` | `-col` | CSV column index to use (default: 0) |
| `--quiet` | `-q` | Suppress non-essential output |
| `--no-color` | - | Disable colored output |
| `--verbose` | `-v` | Enable verbose debug output |
| `--mask` | `-m` | Mask password input |
| `--version` | - | Show version information |

### CLI Examples

```bash
# Check a single password
python password_checker.py -c "MyPassword123"

# Check passwords from CSV (quiet mode)
python password_checker.py -f passwords.csv -q

# Check specific CSV column (e.g., column 2)
python password_checker.py -f passwords.csv --column 2

# Disable colors (useful for CI/CD)
python password_checker.py -f passwords.csv --no-color

# Show version
python password_checker.py --version
```

## Requirements

- **Python 3.x:** The script is written in Python 3.
- **Internet Connection:** An internet connection is required on the first run to download the list of common passwords.
- **External Libraries:** Install the required packages:

```bash
pip install cryptography colorama
```

## How to Use

### Interactive Mode

1. **Open your terminal** (like Command Prompt, PowerShell, or Terminal on macOS/Linux).
2. **Navigate to the directory** where you have saved `password_checker.py`.
3. **Run the script**: `python password_checker.py`
4. **Follow the menu** - Enter 1, 2, 3, or 4 to choose an option.

### CLI Mode

1. Open your terminal.
2. Run the script with options:

```bash
# Single password check
python password_checker.py -c "your_password"

# Batch processing from CSV
python password_checker.py -f path/to/passwords.csv
```

## Output

- Weak passwords and their suggested strong alternatives are saved to `~/Documents/suggested_passwords.txt`
- The file is encrypted with Fernet encryption
- An encryption key is provided after saving - keep it safe to decrypt the file later