import datetime
import pathlib

DEFAULT_TIMEOUT = 1800


class FileLock:
    """
    Utilise un lock file pour empecher plusieurs processus d'operer en meme temps.
    """

    def __init__(self, path_lock, lock_timeout=DEFAULT_TIMEOUT):
        """

        :param path_lock: Path du fichier lock
        :param lock_timeout: Timeout verifie avec la date de modification du lock file.
        """
        self.__file_path = pathlib.Path(path_lock)
        self.__lock_timeout = lock_timeout

    def __enter__(self):
        try:
            with open(self.__file_path, 'x'):
                pass
        except FileExistsError:
            # Verifier si le fichier lock est plus vieux que le timeout
            stat = self.__file_path.stat()
            if stat.st_mtime < datetime.datetime.now().timestamp() - self.__lock_timeout:
                # Ok, lock expire. On touch le fichier
                self.__file_path.touch()
            else:
                # Le lock n'est pas expire
                raise FileLockedException()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__file_path.unlink(missing_ok=True)


class FileLockedException(Exception):
    pass


def is_locked(path_lock, timeout=DEFAULT_TIMEOUT):
    path_lock = pathlib.Path(path_lock)

    if path_lock.exists():
        stat = path_lock.stat()
        if stat.st_mtime > datetime.datetime.now().timestamp() - timeout:
            return True

    return False
