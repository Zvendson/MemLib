from dataclasses import dataclass
from pathlib import Path

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError


@dataclass(kw_only=True)
class Credentials:
    """
    Dataclass for account credentials and options to set.

    :param Name: The custom name of the account
    :param EMail: E-Mail of the account
    :param Password: Password of the account
    :param Path: Local path to an executable
    :param Args: Extra arguments to launch the bot with
    """

    Name:     str             = ""
    EMail:    str             = ""
    Password: str             = ""
    Path:     str             = ""
    Args:     str | list[str] = ""

    def __setattr__(self, name, value):
        if name != "Args":
            self.__dict__[name] = value
            return

        if isinstance(value, list):
            self.__dict__[name] = ' '.join(value)
        elif isinstance(value, str):
            self.__dict__[name] = value
        else:
            self.__dict__[name] = ''


class CredentialManager:
    """
    Class to manage the credentials and extra arguments for an account. The credentials are stored in a KeePass
    database. It is strongly adviced to use a password, to keep your data safe.
    The database will be created if it does not exist.

    :param filepath: The path to the database file.
    :param password: The master password to open the database
    """

    def __init__(self, filepath: Path | str, password: str = None):
        try:
            self._kpf = PyKeePass(filepath, password=password)
        except FileNotFoundError:
            self._kpf = create_database(filepath, password=password)
            self._kpf.save()
        except CredentialsError:
            raise ValueError("Invalid password.")

        except Exception as e:
            raise e

    def GetCredentials(self, groupname: str, name: str) -> Credentials | None:
        """
        :param groupname: The name of the group the credentials are stored under.
        :param name: The name of the credentials.
        :return: The credentials and arguments for the account with the given name or None if the bot does not exist
        """

        group = self._kpf.find_groups(name=groupname, first=True)
        if group is None:
            return None

        entry = self._kpf.find_entries(title=name, first=True, group=group)
        if entry is None:
            return None

        return Credentials(
            Name=entry.title,
            EMail=entry.username,
            Password=entry.password,
            Path=entry.url,
            Args=entry.notes
        )

    def AddCredentials(self, groupname: str, credentials: Credentials) -> bool:
        """
        Adds or updates the credentials. If the account does not exist it will be created. If the account already
        exists, the credentials will be updated.

        :param groupname: The name of the group where the credentials will be stored.
        :param credentials: The credentials

        :return: True if the credentials were added or updated successfully otherwise False.
        """

        group = self._kpf.find_groups(name=groupname, first=True)
        if group is None:
            group = self._kpf.add_group(self._kpf.root_group, groupname)

        entry = self._kpf.find_entries(title=credentials.Name, first=True, group=group)
        if entry is not None:
            self._kpf.delete_entry(entry)

        entry = self._kpf.add_entry(
            group,
            title=credentials.Name,
            username=credentials.EMail,
            password=credentials.Password,
            url=credentials.Path,
            notes=credentials.Args
        )

        self._kpf.save()

        return entry is not None
