from getpass import getpass

from crypto.encrypt import Encryptions
from stores.key_handler import KeyHandler


def create_password():
    print("\n--- Create Password ---")

    print("1. ASCII")
    print("2. Bytes")

    option = input("> ").strip()

    if option == "1":
        choice = "ascii"

    elif option == "2":
        choice = "bytes"

    else:
        print("Invalid option.")
        return

    try:
        length = int(
            input("Password length: ")
        )

    except ValueError:
        print("Length must be a number.")
        return

    pwd, pwd_key, pwd_salt = (
        Encryptions.pwd_gen_w_key(
            choice,
            length
        )
    )

    name = input(
        "Entry name: "
    ).strip()

    filename = f"{name}.jer"

    master_pwd = getpass(
        "Master password: "
    )

    KeyHandler.save_entry(
        filename=filename,
        master_pwd=master_pwd,
        password=pwd,
        pwd_key=pwd_key,
        pwd_salt=pwd_salt
    )

    print(f"\nSaved to {filename}")

    print("\nGenerated password:")
    print(pwd)


def open_password():
    print("\n--- Open Jerry File ---")

    filename = input(
        "File: "
    ).strip()

    master_pwd = getpass(
        "Master password: "
    )

    try:
        data = KeyHandler.load_entry(
            filename,
            master_pwd
        )

    except Exception:
        print(
            "Wrong master password "
            "or corrupted .jer file."
        )
        return

    print("\nPassword:")
    print(data["password"])

    print("\nPassword hash:")
    print(data["password_hash"])

    print("\nKey:")
    print(data["pwd_key"].hex())


def main():
    while True:

        print(
            """
====================
       JERRY
====================

1. Generate password
2. Open .jer file
3. Exit
"""
        )

        option = input("> ").strip()

        if option == "1":
            create_password()

        elif option == "2":
            open_password()

        elif option == "3":
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
