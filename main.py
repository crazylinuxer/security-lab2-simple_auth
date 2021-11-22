import os
from typing import Optional

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


class Menu:
    def __init__(self, repo: Repository):
        self.repository: Repository = repo
        self.current_user: Optional[User] = None
        self.secret_data = "LINUX IS BETTER THAN WINDOWS"
        self.commands = {
            "create user": (self.create_user, "Create a new user"),
            "login": (self.login, "Log into an account"),
            "logout": (self.logout, "Log out of your account"),
            "show account": (self.show_account, "Show your own account"),
            "change permissions": (self.change_permissions, "Make someone an admin or not (only for admins)"),
            "help": (self.help, "Print this help message"),
            "delete user": (self.delete_user, "Delete a given user (only for admins)"),
            "delete my account": (self.delete_own_account, "Delete your own account"),
            "get data": (self.get_data, "Get the secret data"),
            "change data": (self.change_data, "Update the secret data"),
            "exit": (lambda: (print(text_styles.yellow("Exit")), exit()), "Exit the program")
        }

    def create_user(self):
        pass

    def login(self):
        pass

    def logout(self):
        pass

    def show_account(self):
        pass

    def change_permissions(self):
        pass

    def help(self):
        print("List of all commands:")
        for command in self.commands:
            print(text_styles.bold(command), '-', self.commands[command][1])

    def delete_user(self):
        pass

    def delete_own_account(self):
        pass

    def get_data(self):
        pass

    def change_data(self):
        pass

    def interface(self):
        while True:
            command = input(">> ").strip()
            if command in self.commands:
                self.commands[command][0]()
            else:
                print(text_styles.red("Command not found!"))
                self.help()


if __name__ == "__main__":
    try:
        Menu(Repository(f"sqlite:///{os.path.abspath('./data.db')}")).interface()
    except (KeyboardInterrupt, EOFError):
        print(text_styles.yellow("\nExit"))
