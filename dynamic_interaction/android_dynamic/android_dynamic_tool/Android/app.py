from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import getLogger
from typing import TYPE_CHECKING

import androguard
from androguard.core.bytecodes.apk import APK

from ..helper.constants import LOGGER_BASE_NAME
from ..helper.helper_functions import get_file_sha256_hash

from pathlib import Path as Pth

if TYPE_CHECKING:
    from logging import Logger
    from pathlib import Path
    from typing import List, Optional, Set, Union
    from .ui_automator.exploration_session import AndroidExplorationSession


class AndroidApp:
    """Encapsulates information about an Android-app, parsed by androguard."""

    name: str
    apk_path: Path
    app_package: Optional[str]
    launch_activity: Optional[str] = None  # Is only set in special cases
    version_string: Optional[str]
    version_code: Optional[str]
    main_activities: List[str] = list()
    activities: List[str] = list()
    apk_object: Optional[APK]
    apk_hash: str
    install_source: Optional[str]

    def __init__(self, path: Union[str, Path]) -> None:
        """Initializes object and parses APK specified by path using androguard.

        Args:
            path: Path to an APK-file

        Raises:
            FileNotFoundError: If path is not a file.
        """
        if isinstance(path, str):
            path = Pth(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        self.apk_path = path
        self._logger: Logger = getLogger(LOGGER_BASE_NAME + "android.app")

        self.apk_hash = get_file_sha256_hash(self.apk_path)

        self.apk_object = self._parse_apk(self.apk_path)
        if self.apk_object:
            self.name = self.apk_object.get_app_name()
            self.app_package = self.apk_object.get_package()
            self.activities = self.apk_object.get_activities()
            self.main_activities = self.apk_object.get_main_activities()
            self.version_string = self.apk_object.get_androidversion_name()
            self.version_code = self.apk_object.get_androidversion_code()
        elif path.name.lower().endswith(".apk"):
            self.name = self.app_package = path.name[: -len(".apk")]
            self._logger.warning(
                f"Parsing the apk failed, extrapolating app and package name from filename "
                f"({self.name})"
            )
        else:
            self._logger.warning(f"Parsing the apk failed, only setting path and hash")

        if self.name:
            self._logger.info(
                    f'App-Information: name="{self.name}", '
                    f'package_name="{self.app_package}", '
                    f'version="{(self.version_string if self.version_string else "UNKNOWN")}"'
                )

    @staticmethod
    def _parse_apk(path_to_apk: Union[str, Path]) -> Optional[APK]:
        """ Parses an APK given by path_to_apk and returns androguard result.

        Args:
            path_to_apk: Path pointing to APK-file.

        Returns:
            APK if parsing succeeded, None in other cases.

        Raises:
            FileNotFoundError: If path_to_apk is not a file.
        """
        # Suppress warnings issued by androguard
        getLogger(androguard.__name__).setLevel("ERROR")

        logger = getLogger(LOGGER_BASE_NAME + ".android.app.parse_apk")

        if isinstance(path_to_apk, str):
            path_to_apk = Path(path_to_apk)
        if not path_to_apk.is_file():
            raise FileNotFoundError(str(path_to_apk))

        logger.debug(
            f'Parsing "{str(path_to_apk)}" with androguard to obtain metadata of package.'
        )

        try:
            # Only parse manifest file to improve speed
            apk = APK(str(path_to_apk))

        except RuntimeError:
            logger.exception(
                f'There was an exception while parsing "{str(path_to_apk)}"'
            )
            return None

        return apk

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AndroidApp):
            return self.apk_hash == other.apk_hash
        return False

    def __hash__(self) -> int:
        return hash(self.apk_hash)


@dataclass
class AndroidActivity:
    """Holds necessary data to identify and compare Activities."""
    name: str
    package: AndroidAppPackage

    def __hash__(self) -> int:
        return hash((self.name, self.package))

    def __str__(self) -> str:
        return str(self.package) + self.name


@dataclass
class AndroidAppPackage:
    """Holds necessary data to identify and compare Packages."""
    name: str
    activities: Set[AndroidActivity]

    def __init__(self, name: str):
        self.name = name
        self.activities = set()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AndroidAppPackage):
            return self.name == other.name
        return False

    def __hash__(self) -> int:
        return hash(self.name)

    def __str__(self) -> str:
        return self.name


class AndroidAppStarter(ABC):
    """Holds an arbitrary mechanism to install, start and stop an app without Appium"""
    exploration_session: AndroidExplorationSession  # The exploration session running the analysis
    desired_caps = dict  # The Appium configuration (Desired Capabilities) in use
    allow_app_installation: bool = True  # Specifies if the starter is allowed to install the app if it is not installed

    def __init__(self, exploration_session: AndroidExplorationSession) -> None:
        """Initiates an instance of this class.

        Args:
            exploration_session: The exploration session running the analysis
        """
        self.exploration_session = exploration_session

    def setup(self, desired_caps: dict) -> None:
        """A setup routine required to be executed before the app can be started.
        If a subclass inheriting this class overwrites this method, the overwriting method should call this setup()
         routine in its body.

        Args:
            desired_caps: The Appium exploration session configuration (Desired Capabilities) used by the calling
                            exploration session.
        """
        self.desired_caps = desired_caps
        self.prepare_app()

    def install_app(self) -> None:
        """This method installs the target app on the target device if installation is allowed.
        By default, it calls the installation routine of the calling exploration session.
        A subclass can overwrite this method to use an arbitrary different installation mechanism
        """
        if not self.exploration_session.device.app_installed(self.exploration_session.app):
            if self.allow_app_installation:
                self.exploration_session.device.install_app(
                    self.exploration_session.app,
                    grant_runtime_permissions=self.exploration_session.grant_runtime_permissions
                )

    def reset_app(self) -> None:
        """This method resets the target app (deleting user data and configuration) on the target device."""
        self.exploration_session.device.reset_app(self.exploration_session.app)

    def prepare_app(self) -> None:
        """This method prepares the target app for analysis. This includes installing, stopping and resetting it
         if possible."""
        self.install_app()
        self.exploration_session.device.stop_app(self.exploration_session.app)
        if not self.exploration_session.grant_runtime_permissions:
            self.reset_app()

    @abstractmethod
    def start(self):
        """This method is abstract and needs to be implemented by the subclass. It contains the routine to start the
        app. Thereby, it can be assumed that the app was installed already."""
        pass

    @abstractmethod
    def stop(self):
        """This method is abstract and needs to be implemented by the subclass.
         It contains the routine to stop the app."""
        pass
