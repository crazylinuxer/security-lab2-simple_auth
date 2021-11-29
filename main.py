import os
import sys
import tty
import json
import termios
from math import ceil
from time import sleep
from decimal import Decimal
from typing import Optional, Set, AnyStr
from datetime import datetime, timedelta

import bcrypt
from repository import Repository, User

from utils import text_styles


class PasswordException(Exception):
    pass


def check_password(password: str, forbidden_passwords: Optional[Set[str]] = None, min_length: Optional[int] = None):
    if forbidden_passwords and password in forbidden_passwords:
        raise PasswordException("Password is present in the dictionary")
    if min_length and min_length > 0 and len(password) < min_length:
        raise PasswordException("Password is too short")
    letters = bytes(range(b'a'[0], b'z'[0]+1)).decode()
    lower = False
    upper = False
    digit = False
    prev_letter = None
    met_group = False
    for letter in password:
        check = False
        if letters.find(letter) != -1:
            check = True
            lower = True
        if letters.upper().find(letter) != -1:
            check = True
            upper = True
        if "-.?!@=_^:;#$%&*()+\\<>~`/\"'".find(letter) != -1:
            check = True
        if letter.isdigit():
            check = True
            digit = True
        if not check:
            raise PasswordException(f"Password cannot contain symbols like this: '{letter}'")
        if prev_letter and prev_letter == letter:
            if met_group:
                raise PasswordException("Password may only contain one group of 2 identical symbols")
            met_group = True
        prev_letter = letter
    if not lower:
        raise PasswordException("Password must contain at least one lowercase letter")
    if not upper:
        raise PasswordException("Password must contain at least one uppercase letter")
    if not digit:
        raise PasswordException("Password must contain at least one digit")


def is_float(element: AnyStr) -> bool:
    try:
        float(element)
        return True
    except ValueError:
        return False


def read_raw_byte() -> bytes:
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        char = sys.stdin.buffer.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return char


class Menu:
    def __init__(self, repo: Repository):
        self.repository: Repository = repo
        self.current_user: Optional[User] = None
        self._forbidden_passwords = self._read_forbidden_passwords()
        self.wrong_password_delay = None
        self.password_length = None
        self.password_lifetime = None
        self.secret_data = None
        self._load_config()
        self.commands = {
            "create user": (self.create_user, f"Create a new user {text_styles.yellow('(only for admins)')}"),
            "login": (self.login, "Log into an account"),
            "logout": (self.logout, "Log out of your account"),
            "show account": (self.show_account, "Show your own account"),
            "change permissions": (self.change_permissions,
                                   f"Make someone an admin or not {text_styles.yellow('(only for admins)')}"),
            "help": (self.help, "Print this help message"),
            "get data": (self.get_data, "Get the secret data"),
            "set data": (self.change_data, "Update the secret data"),
            "set password life time": (
                self.set_password_lifetime,
                f"Set the time after which user will have to change a password {text_styles.yellow('(only for admins)')}"
            ),
            "get password strength": (self.get_password_strength, "Get an estimate of a password strength on a given config"),
            "exit": (lambda: (print(text_styles.yellow("Exit")), exit()), "Exit the program")
        }

    @staticmethod
    def _read_forbidden_passwords() -> Set[str]:
        result = set()
        with open("./forbidden_passwords/rockyou_short.txt") as passwords:
            result.update(line.strip(' \n') for line in passwords.readlines())
        with open("./forbidden_passwords/names.txt") as names:
            result.update(line.strip(' \n') for line in names.readlines())
        with open("./forbidden_passwords/words.txt") as words:
            result.update(line.strip(' \n').split()[0] for line in words.readlines())
        return result

    def _load_config(self):
        with open("./config.json") as conf_file:
            config = json.load(conf_file)
            self.wrong_password_delay = config["wrong_password_delay"]
            self.password_length = config["password_length"]
            self.password_lifetime = timedelta(seconds=config["password_lifetime"])
            self.secret_data = config["secret_data"]

    def _save_config(self):
        config = {
            "wrong_password_delay": self.wrong_password_delay,
            "password_length": self.password_length,
            "password_lifetime": self.password_lifetime.total_seconds(),
            "secret_data": self.secret_data
        }
        with open("./config.json", 'w') as conf_file:
            json.dump(config, conf_file)

    def check_current_user(self, admin: bool = False, invert: bool = False) -> bool:
        if self.current_user and invert:
            print(
                text_styles.red("You should"),
                text_styles.bold(text_styles.red('not')),
                text_styles.red("be logged in to execute this command")
            )
            return False
        elif not self.current_user and not invert:
            print(text_styles.red("You must log in at first to execute this command"))
            return False
        if self.current_user and not self.current_user.is_admin and admin:
            print(text_styles.red("You must be an admin to execute this command"))
            return False
        return True

    def get_password_strength(self):
        parameters = {
            "L": self.password_length, "A": 88, "T": self.password_lifetime.total_seconds(),
            "V": (60 / (self.wrong_password_delay + 0.5)) * 60
        }
        for parameter, full_name, checker, item_type in (
                ("L", "password length", str.isdecimal, int), ("A", "alphabet length", str.isdecimal, int),
                ("V", "brute-force speed (passwords per hour)", str.isdecimal, int),
                ("T", "password life time (in seconds)", str.isdecimal, int),
                ("desired_P", "desired P ((V*T)/S) to estimate S*", is_float, float)
        ):
            while True:
                entered_parameter = input(
                    f"Input the {text_styles.bold(full_name)}" +
                    (f" {text_styles.yellow(f'(or just hit enter to use {parameters[parameter]})')}: " if
                        parameters.get(parameter) else ': ')
                )
                if not entered_parameter and parameter in parameters:
                    break
                if checker(entered_parameter):
                    parameters[parameter] = item_type(entered_parameter)
                    break
                print(text_styles.red("Invalid value"))
        parameters["S"] = parameters["A"] ** parameters["L"]
        parameters["P"] = Decimal((parameters["V"] * parameters["T"]) / parameters["S"])
        if parameters["P"] > 1:
            parameters["P"] = 1
        print("S = A^L =\t", parameters["S"])
        print("P = (V*T)/S =\t", f'{parameters["P"]:.32f}')
        if parameters.get("desired_P"):
            parameters["S*"] = ceil(parameters["V"] * parameters["T"] / parameters["desired_P"])
            print("S* = [(V*T)/P] =", parameters["S*"])

    def set_password_lifetime(self):
        if not self.check_current_user(admin=True):
            return
        while True:
            time = input("Enter the time in seconds: ")
            if time.isdecimal():
                break
            print(text_styles.red("Invalid value given"))
        self.password_lifetime = timedelta(seconds=int(time))
        print(text_styles.green("Value changed successfully"))

    def create_user(self):
        if not self.check_current_user(admin=True):
            return
        while True:
            username = input("Input the username of the new user (it must be unique): ")
            if self.repository.get_user_by_username(username):
                print("Error: such user already exists")
            else:
                break
        user = User(
            username=username,
            first_name=input("Input the first name of the new user (it must be unique): "),
            last_name=input("Input the last name of the new user (it must be unique): "),
            is_admin=bool(input("Should this user be an admin? [y/N] ") in ('y', 'Y'))
        )
        self.repository.add_or_update_user(user)
        print(text_styles.green("User was successfully created"))

    @staticmethod
    def _input_password(invitation: str) -> bytes:
        password = b''
        print(invitation, end='', flush=True)
        while True:
            current_symbol = read_raw_byte()
            if current_symbol in (b'\r', b'\n'):
                print()
                break
            elif current_symbol in (b'\x03', b'\x04'):
                print('\r' + text_styles.grey(invitation) + (' ' * len(password)), end=' ')
                raise KeyboardInterrupt
            if current_symbol == b'\x7f':
                password = password[:-1]
            else:
                password += current_symbol
            print('\r' + invitation + ('*' * len(password)) + ' ', end=chr(8), flush=True)
        return password

    def _input_new_password(self, invitation1: str, invitation2: str, old_password: Optional[str] = None) -> bytes:
        while True:
            new_password = self._input_password(invitation1)
            try:
                if old_password and old_password == new_password.decode():
                    raise PasswordException("You can't use your old password")
                check_password(new_password.decode(), self._forbidden_passwords)
                if new_password != self._input_password(invitation2):
                    raise PasswordException("The passwords you entered are different")
                break
            except PasswordException as ex:
                print(text_styles.red(ex.args[0]))
        return new_password

    def login(self):
        if not self.check_current_user(admin=False, invert=True):
            return
        username = input("Input your username: ")
        password = self._input_password("Input your password: ")
        user = self.repository.get_user_by_username(username)
        if not user or (user.password_hash and not bcrypt.checkpw(
                password, user.password_hash.encode() if isinstance(user.password_hash, str) else user.password_hash
        )):
            sleep(self.wrong_password_delay)
            print(text_styles.red("Incorrect username or password"))
            return
        if not user.password_hash:
            print(text_styles.bold(text_styles.yellow("Warning: your account does not have a password")))
            new_password = self._input_new_password("Input your new password: ", "Re-enter the password: ")
            user.password_hash = bcrypt.hashpw(new_password, bcrypt.gensalt(13))
            user.password_set = datetime.utcnow()
            self.repository.add_or_update_user(user)
            print(text_styles.green("Password was set successfully"))
        elif not user.password_set or datetime.utcnow() - user.password_set > self.password_lifetime:
            print(text_styles.yellow(text_styles.bold("Warning: your password is old and should be replaced with a new one")))
            new_password = self._input_new_password("Input your new password: ", "Re-enter the password: ", password.decode())
            user.password_hash = bcrypt.hashpw(new_password, bcrypt.gensalt(13))
            user.password_set = datetime.utcnow()
            self.repository.add_or_update_user(user)
        self.current_user = user
        print(text_styles.green("You logged in successfully"))

    def logout(self):
        if not self.check_current_user(admin=False):
            return
        self.current_user = None
        print(text_styles.green("You logged out successfully"))

    def show_account(self):
        if not self.check_current_user(admin=False):
            return
        print(text_styles.yellow("Current user info:"))
        print("Username:", text_styles.bold(self.current_user.username))
        print("First name:", text_styles.bold(self.current_user.first_name))
        print("Last name:", text_styles.bold(self.current_user.last_name))
        print("Admin:", text_styles.bold(
            (text_styles.green if self.current_user.is_admin else text_styles.red)(str(self.current_user.is_admin))
        ))

    def change_permissions(self):
        if not self.check_current_user(admin=True):
            return
        while not (user := self.repository.get_user_by_username(input("Input the username of desired user: "))):
            print(text_styles.red("User not found"))
        if user.id == self.current_user.id:
            print("You can not change your own permissions")
            return
        if user.is_admin:
            print("This user is an administrator")
            if input("Do you really want to take admin rights away from this user? [y/N] ") in ('y', 'Y'):
                user.is_admin = False
            else:
                print(text_styles.yellow("Cancelled"))
                return
        else:
            print("This user is not an administrator")
            if input("Do you really want to grant admin rights to this user? [y/N] ") in ('y', 'Y'):
                user.is_admin = True
            else:
                print(text_styles.yellow("Cancelled"))
                return
        self.repository.add_or_update_user(user)
        print(text_styles.green("Rights changed successfully"))

    def help(self):
        print(text_styles.yellow("List of all commands:"))
        for command in self.commands:
            print(text_styles.bold(text_styles.cyan(command)), '-', self.commands[command][1])

    def get_data(self):
        if not self.check_current_user(admin=False):
            return
        print(self.secret_data)

    def change_data(self):
        if not self.check_current_user(admin=False):
            return
        self.secret_data = input("Set the new value of data: ")
        print(text_styles.green("The value was set successfully"))

    def interface(self):
        while True:
            try:
                command = input(">> ").strip()
                if not command:
                    continue
                if command in self.commands:
                    try:
                        self.commands[command][0]()
                    except KeyboardInterrupt:
                        print(text_styles.yellow("\nCancelled"))
                else:
                    print(text_styles.red("Command not found!"))
                    self.help()
            except KeyboardInterrupt:
                print()
                pass
            finally:
                self._save_config()


if __name__ == "__main__":
    try:
        Menu(Repository(f"sqlite:///{os.path.abspath('./data.db')}")).interface()
    except EOFError:
        print(text_styles.yellow("\nExit"))
