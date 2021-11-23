import os
import sys
import tty
import termios
from typing import Optional
from time import sleep

import bcrypt
from repository import Repository, User

from utils import text_styles


secret_data = "asdfasdfasdf"


class PasswordException(Exception):
    pass


def check_password(password: str):
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
        self.secret_data = "LINUX IS BETTER THAN WINDOWS"
        self.commands = {
            "create user": (self.create_user, f"Create a new user {text_styles.yellow('(only for admins)')}"),
            "login": (self.login, "Log into an account"),
            "logout": (self.logout, "Log out of your account"),
            "show account": (self.show_account, "Show your own account"),
            "change permissions": (self.change_permissions,
                                   f"Make someone an admin or not {text_styles.yellow('(only for admins)')}"),
            "help": (self.help, "Print this help message"),
            # "delete user": (self.delete_user, f"Delete a given user {text_styles.yellow('(only for admins)')}"),
            # "delete my account": (self.delete_own_account, f"Delete your own account"),
            "get data": (self.get_data, "Get the secret data"),
            "set data": (self.change_data, "Update the secret data"),
            "exit": (lambda: (print(text_styles.yellow("Exit")), exit()), "Exit the program")
        }

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
            password_hash=None,
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
                break
            elif current_symbol in (b'\x03', b'\x04'):
                print('\r' + (' ' * len(invitation)) + (' ' * len(password)) + ' ')
                raise KeyboardInterrupt
            if current_symbol == b'\x7f':
                password = password[:-1]
            else:
                password += current_symbol
            print('\r' + invitation + ('*' * len(password)) + ' ', end=chr(8), flush=True)
        print()
        return password

    def _input_new_password(self, invitation: str) -> bytes:
        while True:
            new_password = self._input_password(invitation)
            try:
                check_password(new_password.decode())
                break
            except PasswordException as ex:
                print(text_styles.red(ex.args[0]))
        return new_password

    def login(self):
        if not self.check_current_user(admin=False, invert=True):
            return
        username = input("Input your username: ")
        try:
            password = self._input_password("Input your password: ")
        except KeyboardInterrupt:
            return
        user = self.repository.get_user_by_username(username)
        if not user or (user.password_hash and not bcrypt.checkpw(password, user.password_hash.encode())):
            sleep(1)
            print(text_styles.red("Incorrect username or password"))
            return
        if not user.password_hash:
            print(text_styles.bold(text_styles.yellow("Warning: your account does not have a password")))
            try:
                new_password = self._input_new_password("Input your new password: ")
            except KeyboardInterrupt:
                return
            user.password_hash = bcrypt.hashpw(new_password, bcrypt.gensalt(14))
            self.repository.add_or_update_user(user)
            print(text_styles.green("Password was set successfully"))
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

    # def delete_user(self):
    #     pass
    #
    # def delete_own_account(self):
    #     pass

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


if __name__ == "__main__":
    try:
        Menu(Repository(f"sqlite:///{os.path.abspath('./data.db')}")).interface()
    except EOFError:
        print(text_styles.yellow("\nExit"))
