import csv
from os.path import getmtime
from cryptography.fernet import Fernet
import urllib.request
import secrets
import string
import os
import logging
import time
import argparse
import sys
from colorama import Fore, Style, init

VERSION = "1.2.0"

RATE_LIMIT_SECONDS = 5
MAX_CHECKS_PER_MINUTE = 20

rate_limiter = {"last_check": 0, "checks_today": 0, "reset_time": 0}


def get_crossplatform_documents_path():
    """Returns the correct Documents folder path for the current OS."""
    if os.name == "nt":
        return os.path.join(os.environ.get("USERPROFILE", ""), "Documents")
    elif os.name == "posix":
        if os.uname().sysname == "Darwin":
            return os.path.join(os.path.expanduser("~"), "Documents")
        else:
            return os.path.expanduser("~/Documents")
    else:
        return os.path.expanduser("~/Documents")


def check_rate_limit():
    """Check if the user has exceeded the rate limit for password checks."""
    current_time = time.time()
    if current_time - rate_limiter["reset_time"] > 60:
        rate_limiter["checks_today"] = 0
        rate_limiter["reset_time"] = current_time
    
    if rate_limiter["checks_today"] >= MAX_CHECKS_PER_MINUTE:
        wait_time = 60 - (current_time - rate_limiter["reset_time"])
        return False, wait_time
    
    if current_time - rate_limiter["last_check"] < RATE_LIMIT_SECONDS:
        wait_time = RATE_LIMIT_SECONDS - (current_time - rate_limiter["last_check"])
        return False, wait_time
    
    rate_limiter["last_check"] = current_time
    rate_limiter["checks_today"] += 1
    return True, 0

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console()


def confirm_action(message, default=False, use_rich=True):
    """Ask user for confirmation with cross-platform support."""
    if use_rich and RICH_AVAILABLE:
        return Confirm.ask(message, default=default)
    else:
        suffix = " [Y/n]: " if default else " [y/N]: "
        response = input(message + suffix).strip().lower()
        if not response:
            return default
        return response in ["y", "yes"]


def parse_args():
    parser = argparse.ArgumentParser(
        prog="password_checker",
        description="Check password strength and generate secure alternatives",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", "-c", metavar="PASSWORD", help="Check a single password")
    parser.add_argument("--file", "-f", metavar="FILE", help="Check passwords from a CSV file")
    parser.add_argument("--column", "-col", type=int, default=0, metavar="N", help="CSV column index to use (default: 0)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--no-tui", action="store_true", help="Disable TUI (use simple text mode)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--mask", "-m", action="store_true", help="Mask password input")
    parser.add_argument("--version", action="store_true", help="Show version information")
    return parser.parse_args()


def init_colorama(no_color):
    if no_color:
        global Fore, Style
        class Fore:
            RED = YELLOW = GREEN = ""
        class Style:
            RESET_ALL = BRIGHT = ""
    else:
        init()


def get_password_input(mask=False, prompt="Enter the password to check: "):
    if mask:
        import getpass
        return getpass.getpass(prompt)
    return input(prompt)


def generate_secure_password(length=16):
    """
    Generates a cryptographically strong password.

    It uses the `secrets` module for secure random number generation.
    The password is guaranteed to contain at least one lowercase letter,
    one uppercase letter, one digit, and one special character.

    Args:
        length (int): Password length (default 16)

    Returns:
        str: A securely generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
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


def save_suggested_passwords(weak_passwords, file_path, use_rich=True, confirm_overwrite=True):
    if not weak_passwords:
        return None, None
    
    key = None
    
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
        
    if key is None:
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)

    fernet = Fernet(key)

    file_name = "suggested_passwords.txt"
    documents_path = get_crossplatform_documents_path()
    
    if not os.path.exists(documents_path):
        os.makedirs(documents_path, exist_ok=True)
    
    full_path = os.path.join(documents_path, file_name)
    
    if confirm_overwrite and os.path.exists(full_path):
        overwrite = confirm_action(
            f"File {full_path} already exists. Overwrite?",
            default=False,
            use_rich=use_rich
        )
        if not overwrite:
            return None, None
    
    content = ""
    for weak, strong in weak_passwords.items():
        content += f"Weak Password: {weak}, Suggested Strong Password: {strong}\n"
    
    encrypted = fernet.encrypt(content.encode())

    with open(full_path, "wb") as file:
        file.write(encrypted)
    
    return full_path, key.decode()


def load_encrypted_passwords(file_path):
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption.key")
    if not os.path.exists(key_path):
        print("No encryption key found.")
        return None
    
    with open(key_path, "rb") as f:
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


def display_password_result(password, weaknesses, score, use_rich=True):
    if use_rich and RICH_AVAILABLE:
        if score == "Low Grade of security":
            color = "red"
        elif score == "Medium Grade of security":
            color = "yellow"
        else:
            color = "green"
        
        console.print(f"\n[bold]Password:[/bold] {'*' * len(password) if len(password) > 4 else password}")
        console.print(f"[bold {color}]Score: {score}[/bold {color}]")
        
        if weaknesses:
            console.print("\n[bold red]Weaknesses:[/bold red]")
            for w in weaknesses:
                console.print(f"  [red]•[/red] {w}")
            
            strong = generate_secure_password()
            console.print(f"\n[bold green]Suggested Strong Password:[/bold green] [cyan]{strong}[/cyan]")
    else:
        color = Fore.RED if score == "Low Grade of security" else Fore.YELLOW if score == "Medium Grade of security" else Fore.GREEN
        print(f"\nPassword: {'*' * len(password) if len(password) > 4 else password}")
        print(f"{color}Score: {score}{Style.RESET_ALL}")
        
        if weaknesses:
            print("\nWeaknesses:")
            for w in weaknesses:
                print(f"  - {w}")
            
            strong = generate_secure_password()
            print(f"\nSuggested Strong Password: {strong}")


def display_batch_results(weak_passwords, full_path, key, use_rich=True):
    if use_rich and RICH_AVAILABLE:
        table = Table(title="Weak Passwords Found", box=box.ROUNDED)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Weak Password", style="red")
        table.add_column("Suggested Strong Password", style="green")
        
        for i, (weak, strong) in enumerate(weak_passwords.items(), 1):
            table.add_row(str(i), weak, strong)
        
        console.print(table)
        console.print(f"\n[bold green]Passwords saved to:[/bold green] {full_path}")
        console.print(f"[bold yellow]Encryption Key (save this!):[/bold yellow] [cyan]{key}[/cyan]")
        console.print("\n[dim]You can decrypt using option 3 in the main menu.[/dim]")
    else:
        print(f"\nFound {len(weak_passwords)} weak passwords:")
        for i, (weak, strong) in enumerate(weak_passwords.items(), 1):
            print(f"  {i}. {weak} -> {strong}")
        print(f"\nPasswords saved to: {full_path}")
        print(f"Encryption Key: {key}")


def tui_menu(common_passwords, no_tui=False):
    use_rich = RICH_AVAILABLE and not no_tui
    
    while True:
        if use_rich:
            console.print(Panel.fit(
                "[bold cyan]Password Strength Checker[/bold cyan]\n"
                "[dim]Choose an option below[/dim]",
                border_style="cyan"
            ))
            console.print("[bold]1.[/bold] Check a single password")
            console.print("[bold]2.[/bold] Enter the path to a CSV file")
            console.print("[bold]3.[/bold] Decrypt saved passwords")
            console.print("[bold]4.[/bold] Exit")
            choice = Prompt.ask("[bold]Enter your choice[/bold]", choices=["1", "2", "3", "4"], default="4")
        else:
            print("\nChoose an option:")
            print("1. Check a single password")
            print("2. Enter the path to a CSV file")
            print("3. Decrypt saved passwords")
            print("4. Exit")
            choice = input("Enter your choice (1, 2, 3, or 4): ")

        if choice == "1":
            allowed, wait_time = check_rate_limit()
            if not allowed:
                if use_rich:
                    console.print(f"[bold red]Rate limit exceeded. Please wait {wait_time:.1f} seconds.[/bold red]")
                else:
                    print(f"Rate limit exceeded. Please wait {wait_time:.1f} seconds.")
                time.sleep(wait_time)
                allowed, _ = check_rate_limit()
                if not allowed:
                    continue
            
            if use_rich:
                password = Prompt.ask("[bold]Enter password to check[/bold]", password=True)
            else:
                password = get_password_input(mask=True)
            
            weaknesses, score = check_password_weaknesses(password, common_passwords)
            display_password_result(password, weaknesses, score, use_rich)
            
        elif choice == "2":
            if use_rich:
                file_path = Prompt.ask("[bold]Enter path to CSV file[/bold]")
            else:
                file_path = input("Enter the path to the CSV file containing passwords: ")
            
            column = 0
            if use_rich:
                col_input = Prompt.ask("[bold]Column index (default: 0)[/bold]", default="0")
                if col_input.isdigit():
                    column = int(col_input)
            else:
                col_input = input("Column index (default: 0): ")
                if col_input.isdigit():
                    column = int(col_input)
            
            weak_passwords = {}
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    reader = csv.reader(file)
                    total = sum(1 for row in reader)
                    file.seek(0)
                    reader = csv.reader(file)
                    current = 0
                    
                    if use_rich and RICH_AVAILABLE:
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            TaskProgressColumn(),
                            console=console
                        ) as progress:
                            task = progress.add_task(f"[cyan]Checking {total} passwords...", total=total)
                            for row in reader:
                                current += 1
                                if len(row) <= column or not row[column].strip():
                                    progress.update(task, advance=1)
                                    continue
                                password = row[column]
                                weaknesses, score = check_password_weaknesses(password, common_passwords)
                                if weaknesses:
                                    weak_passwords[password] = generate_secure_password()
                                progress.update(task, advance=1)
                    else:
                        for row in reader:
                            current += 1
                            if len(row) <= column or not row[column].strip():
                                continue
                            print(f"Checking Password {current} of {total}...", end="\r", flush=True)
                            password = row[column]
                            weaknesses, score = check_password_weaknesses(password, common_passwords)
                            if weaknesses:
                                weak_passwords[password] = generate_secure_password()
                        print()
                
                if weak_passwords:
                    full_path, key = save_suggested_passwords(weak_passwords, file_path, use_rich=use_rich)
                    if full_path:
                        display_batch_results(weak_passwords, full_path, key, use_rich)
                else:
                    if use_rich:
                        console.print("[green]No weak passwords found in the CSV file.[/green]")
                    else:
                        print("No weak passwords found in the CSV file.")
            except FileNotFoundError:
                if use_rich:
                    console.print(f"[red]File not found: {file_path}[/red]")
                else:
                    logging.error(f"File not found: {file_path}")
            except Exception as e:
                if use_rich:
                    console.print(f"[red]An error occurred: {e}[/red]")
                else:
                    logging.error(f"An error occurred: {e}")
                    
        elif choice == "3":
            if use_rich:
                console.print("[bold]Decrypt options:[/bold]")
                console.print("[bold]1.[/bold] Use key from file (encryption.key)")
                console.print("[bold]2.[/bold] Enter key manually")
                decrypt_choice = Prompt.ask("[bold]Enter your choice[/bold]", choices=["1", "2"], default="1")
            else:
                print("\nDecrypt options:")
                print("1. Use key from file (encryption.key)")
                print("2. Enter key manually")
                decrypt_choice = input("Enter your choice (1 or 2): ")
            
            if decrypt_choice == "1":
                if use_rich:
                    encrypted_file = Prompt.ask("[bold]Enter path to encrypted file[/bold]", default="~/Documents/suggested_passwords.txt")
                else:
                    encrypted_file = input("Enter path to encrypted file: ")
                
                result = load_encrypted_passwords(os.path.expanduser(encrypted_file))
                if result and use_rich:
                    console.print(Panel(result, title="Decrypted Content", border_style="green"))
                elif result:
                    print(f"\n{result}")
            elif decrypt_choice == "2":
                if use_rich:
                    key_input = Prompt.ask("[bold]Enter encryption key[/bold]", password=True)
                    encrypted_file = Prompt.ask("[bold]Enter path to encrypted file[/bold]", default="~/Documents/suggested_passwords.txt")
                else:
                    key_input = input("Enter your encryption key: ").strip()
                    encrypted_file = input("Enter path to encrypted file: ")
                
                if len(key_input) < 32:
                    if use_rich:
                        console.print("[red]Invalid key format. Key should be 44 characters (base64-encoded)[/red]")
                    else:
                        print("Invalid key format. Key should be 44 characters (base64-encoded)")
                    continue
                
                try:
                    fernet = Fernet(key_input.encode())
                    with open(os.path.expanduser(encrypted_file), "rb") as f:
                        encrypted_content = f.read()
                    decrypted = fernet.decrypt(encrypted_content)
                    if use_rich:
                        console.print(Panel(decrypted.decode(), title="Decrypted Content", border_style="green"))
                    else:
                        print(f"\n{decrypted.decode()}")
                except Exception as e:
                    if use_rich:
                        console.print(f"[red]Failed to decrypt: Invalid key or file[/red]")
                    else:
                        print("Failed to decrypt: Invalid key or file")
            else:
                if use_rich:
                    console.print("[red]Invalid choice.[/red]")
                else:
                    print("Invalid choice.")
                    
        elif choice == "4":
            if use_rich:
                console.print("[cyan]Exiting the program. Stay secure![/cyan]")
            else:
                print("Exiting the program.")
            break


def main():
    args = parse_args()
    
    init_colorama(args.no_color)
    
    use_rich = RICH_AVAILABLE and not args.no_tui and not args.no_color
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO)
    
    if args.version:
        print(f"Password Checker v{VERSION}")
        return
    
    common_passwords = get_common_passwords()
    
    if args.check:
        allowed, wait_time = check_rate_limit()
        if not allowed:
            print(f"Rate limit exceeded. Please wait {wait_time:.1f} seconds.")
            return
        
        password = args.check
        weaknesses, score = check_password_weaknesses(password, common_passwords)
        display_password_result(password, weaknesses, score, use_rich)
        return
    
    if args.file:
        file_path = args.file
        column = args.column
        weak_passwords = {}
        
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                reader = csv.reader(file)
                total = sum(1 for row in reader)
                file.seek(0)
                reader = csv.reader(file)
                current = 0
                
                if use_rich and RICH_AVAILABLE:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        console=console
                    ) as progress:
                        task = progress.add_task(f"[cyan]Checking {total} passwords...", total=total)
                        for row in reader:
                            current += 1
                            if len(row) <= column or not row[column].strip():
                                progress.update(task, advance=1)
                                continue
                            password = row[column]
                            weaknesses, score = check_password_weaknesses(password, common_passwords)
                            if weaknesses:
                                weak_passwords[password] = generate_secure_password()
                            progress.update(task, advance=1)
                else:
                    for row in reader:
                        current += 1
                        if len(row) <= column or not row[column].strip():
                            continue
                        if not args.quiet:
                            print(f"Checking Password {current} of {total}...", end="\r", flush=True)
                        password = row[column]
                        weaknesses, score = check_password_weaknesses(password, common_passwords)
                        if weaknesses:
                            weak_passwords[password] = generate_secure_password()
                    if not args.quiet:
                        print()
            
            if weak_passwords:
                full_path, key = save_suggested_passwords(weak_passwords, file_path, use_rich=use_rich)
                if full_path:
                    display_batch_results(weak_passwords, full_path, key, use_rich)
            else:
                if not args.quiet:
                    if use_rich:
                        console.print("[green]No weak passwords found in the CSV file.[/green]")
                    else:
                        print("No weak passwords found in the CSV file.")
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        return
    
    tui_menu(common_passwords, args.no_tui)


if __name__ == "__main__":
    main()