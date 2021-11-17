import os

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
    if not lower:
        raise PasswordException("Password must contain at least one lowercase letter")
    if not upper:
        raise PasswordException("Password must contain at least one uppercase letter")
    if not digit:
        raise PasswordException("Password must contain at least one digit")


class Menu:
    pass


def main():
    repository = Repository(f"sqlite:///{os.path.abspath('./data.db')}")
    menu = Menu(repository)
    while True:
        menu()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(text_styles.yellow("Exit"))
