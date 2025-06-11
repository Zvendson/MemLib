"""
Credential management for KeePass databases.

This module provides tools to store, retrieve, and manage account credentials
using a KeePass database file (`.kdbx`). It defines a Credentials dataclass and
a CredentialManager for interacting with account information securely.

Features:
    * Read and write credentials to a KeePass database.
    * Auto-creates the database if it does not exist.
    * Supports groups and extra argument fields.
    * Integrates with `pykeepass` for all operations.

Example:
    from CredentialManager import CredentialManager, Credentials

    manager = CredentialManager('vault.kdbx', password='secret')
    creds = Credentials(name='MyAccount', e_mail='me@mail.com', password='pw123')
    manager.add_credentials('Social', creds)
    loaded = manager.get_credentials('Social', 'MyAccount')

References:
    https://github.com/libkeepass/pykeepass
    https://keepass.info/help/base/index.html
"""

from dataclasses import dataclass
from pathlib import Path

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError



@dataclass(kw_only=True)
class Credentials:
    """
    Stores account credentials and extra arguments for an account.

    Fields:
        name (str): Custom name for the account entry.
        e_mail (str): E-mail address associated with the account.
        password (str): Account password.
        url (str): URL to the account login.
        args (str | list[str]): Extra arguments.

    Note:
        The 'args' field can be a single string or a list of strings. Lists will be joined with spaces.
    """

    name: str = ""
    e_mail: str = ""
    password: str = ""
    url: str = ""
    args: str | list[str] = ""

    def __setattr__(self, name, value):
        """
        Sets the attribute value for the Credentials dataclass.
        The 'args' field is normalized to a string, even if a list is provided.
        """
        if name != "args":
            super().__setattr__(name, value)
            return

        if isinstance(value, list):
            super().__setattr__(name, ' '.join(value))
        elif isinstance(value, str):
            super().__setattr__(name, value)
        else:
            super().__setattr__(name, '')

class CredentialManager:
    """
    Manages credentials and extra arguments for accounts stored in a KeePass database.

    The database is created automatically if it does not exist. It is strongly recommended to use a master password
    for your database to keep your data safe.

    Parameters:
        filepath (Path | str): Path to the KeePass database file.
        password (str, optional): Master password for the database.

    Raises:
        ValueError: If the master password is invalid.
        Exception: For any other error when opening or creating the database.
    """

    def __init__(self, filepath: Path | str, password: str = None):
        """
        Initializes the CredentialManager, opening or creating the KeePass database at the specified path.

        Args:
            filepath (Path | str): Path to the database file.
            password (str, optional): Master password to open or create the database.

        Raises:
            ValueError: If the password is invalid.
            Exception: For any other error in database handling.
        """
        try:
            self._kpf = PyKeePass(filepath, password=password)
        except FileNotFoundError:
            self._kpf = create_database(filepath, password=password)
            self._kpf.save()
        except CredentialsError:
            raise ValueError("Invalid password.")

        except Exception as e:
            raise e

    def get_credentials(self, group_name: str, name: str) -> Credentials | None:
        """
        Retrieves credentials and extra arguments for a given account name in the specified group.

        Args:
            group_name (str): Name of the group under which credentials are stored.
            name (str): Name of the credential entry (account name).

        Returns:
            Credentials | None: The credentials and arguments for the account, or None if not found.
        """

        group = self._kpf.find_groups(name=group_name, first=True)
        if group is None:
            return None

        entry = self._kpf.find_entries(title=name, first=True, group=group)
        if entry is None:
            return None

        return Credentials(
            name=entry.title,
            e_mail=entry.username,
            password=entry.password,
            url=entry.url,
            args=entry.notes
        )

    def add_credentials(self, group_name: str, credentials: Credentials) -> bool:
        """
        Adds or updates credentials for an account in the specified group.

        If the account already exists, its credentials will be updated. Otherwise, a new entry is created.

        Args:
            group_name (str): Name of the group where the credentials will be stored.
            credentials (Credentials): Credentials to add or update.

        Returns:
            bool: True if credentials were added or updated successfully, False otherwise.

        Note:
            The KeePass database is automatically saved after the operation.
        """

        group = self._kpf.find_groups(name=group_name, first=True)
        if group is None:
            group = self._kpf.add_group(self._kpf.root_group, group_name)

        entry = self._kpf.find_entries(title=credentials.name, first=True, group=group)
        if entry is not None:
            self._kpf.delete_entry(entry)

        entry = self._kpf.add_entry(
            group,
            title=credentials.name,
            username=credentials.e_mail,
            password=credentials.password,
            url=credentials.url,
            notes=credentials.args
        )

        self._kpf.save()

        return entry is not None
