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
- **TUI (Terminal User Interface):** Rich interactive interface with progress bars, tables, and colored output.
- **CLI Support:** Use command-line arguments for automation.
- **Cross-Platform:** Works on Windows, Linux, and macOS with automatic Documents folder detection.
- **Clear Feedback and Suggestions:** Provide clear feedback on the weaknesses of your password and offer secure suggestions for improvement.
- **Interactive Prompts:** Use an interactive menu to navigate through options and easily check passwords.
- **Rate Limiting:** Built-in protection against brute-force attacks (max 20 checks per minute).
- **Safe File Handling:** Confirmation prompts before overwriting existing files.

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
| `--no-color` | - | Disable colored/TUI output |
| `--no-tui` | - | Disable TUI (use simple text mode) |
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

## Installation

### Quick Start (Automatic Setup)

```bash
python setup.py
```

This will automatically install all required dependencies.

### Manual Installation

If you prefer to install manually, you need these packages:

**Required (must be installed):**
```bash
pip install cryptography colorama
```

**Optional (for TUI):**
```bash
pip install rich
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

- Weak passwords and their suggested strong alternatives are saved to the user's Documents folder:
  - **Windows:** `C:\Users\<username>\Documents\suggested_passwords.txt`
  - **macOS/Linux:** `~/Documents/suggested_passwords.txt`
- The file is encrypted with Fernet encryption
- An encryption key is provided after saving - keep it safe to decrypt the file later
- The encryption key is stored in the same directory as the script (`encryption.key`)

## Security Features

- **Rate Limiting:** Maximum 20 password checks per minute to prevent brute-force attacks
- **Secure Key Storage:** Encryption keys are stored alongside the script
- **Input Validation:** All inputs are validated before processing
- **Safe Overwrites:** Confirmation required before overwriting existing files