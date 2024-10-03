from __future__ import annotations

import logging
import time
from typing import List, Optional, Type, TYPE_CHECKING

from appium import webdriver
from selenium.common.exceptions import WebDriverException
from urllib3.exceptions import MaxRetryError
# Import Appium UiAutomator2 driver for Android platforms (AppiumOptions)
from appium.options.android import UiAutomator2Options


from ..device import AndroidDevice
from ..ui_automator.app_model import AndroidAppModel
from ..ui_automator.constants import ANDROID_HOME_KEY_CODE
from ...common.exploration_session import ExplorationSession
from ...common.exploration_benchmarks import ExplorationBenchmark
from ...helper.constants import LOGGER_BASE_NAME

if TYPE_CHECKING:
    from ..app import AndroidApp, AndroidAppStarter
    from .exploration_strategies import AndroidExplorationStrategy
    from ...helper.storage_helper import StorageHelper


logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".exploration-sessions")


class AndroidExplorationSession(ExplorationSession):
    """Holds all data necessary for exploration, manages Appium session."""
    app: AndroidApp
    app_model: AndroidAppModel
    app_starter: Optional[AndroidAppStarter] = None
    appium_wd: webdriver.Remote
    command_executor: str
    device: AndroidDevice
    explorer: AndroidExplorationStrategy
    install_app: bool
    grant_runtime_permissions: bool = False
    do_pcap_analysis: bool = False
    text_input_list: Optional[List[str]] = None
    capture_network_traffic_with_pcapdroid: bool = False

    def __init__(
        self,
        command_executor: str,
        device: AndroidDevice,
        app: AndroidApp,
        install_app_from_apk: bool = True,
        reinstall_app: bool = True
    ):
        """Initializes session with given data.

        Args:
            command_executor: Address of the Appium instance.
            device: Android device the app is to be run on.
            app: Information about the app to be explored
            install_app_from_apk: If True, the app is installed from APK before analysis.
                                 Else it is assumed that the app is already installed. Defaults to True.
        """
        self.command_executor = command_executor
        self.device = device
        self.app = app
        self.install_app = install_app_from_apk
        self.reinstall_app = reinstall_app

    def start(self) -> None:
        """Starts an Appium-session using the device and app provided during initialization. Initializes AppModel.

        Raises:
            MaxRetryError: If Appium does not respond.
            WebDriverException: If an unexpected error is encountered by Appium during session start.
        """
        if not hasattr(self, "appium_wd") or not self.appium_wd:
            start_activity = None
            # If path to APK is specified, Appium collects necessary information on its own
            if not self.install_app:
                # If Start-Activity is not already specified and there are main activities available,
                # use one whose name starts with the package name
                if not self.app.launch_activity and self.app.main_activities:
                    start_activities = [
                        activity
                        for activity in self.app.main_activities
                        if activity.startswith(self.app.app_package)
                    ]
                    if start_activities:
                        start_activity = start_activities[0]
                    else:
                        # Catch rare edge case where no main activity name is starting with package_name
                        start_activity = [
                            activity for activity in self.app.main_activities
                        ][0]
                else:
                    start_activity = self.app.launch_activity

            desired_caps = {
                "platformName": "Android",
                "automationName": "UiAutomator2",
                "platformVersion": self.device.platform_version,
                "app": (str(self.app.apk_path) if self.install_app else None),
                "deviceName": self.device.name,
                "udid": self.device.udid,
                "newCommandTimeout": 600,
                "avd": self.device.avd_name,
                "appPackage": self.app.app_package,
                "appActivity": start_activity,
                # If app.app_activity is not explicitly set, allow all activities of the package in order to handle
                # init activities different from the main activity specified in AndroidManifest.xml
                "appWaitActivity": (
                    "*" if not self.app.launch_activity else self.app.launch_activity
                ),
                "autoGrantPermissions": True,
                # Reset and uninstall app before running tests
                "fullReset": self.install_app,
            }

            if self.app_starter is not None:
                desired_caps["autoLaunch"] = False
                logger.debug("appium:autoLaunch = False")

            if self.app_starter is not None or (self.grant_runtime_permissions and self.install_app):
                desired_caps["fullReset"] = False
                desired_caps["noReset"] = True

            if self.grant_runtime_permissions and self.install_app:
                if self.device.app_installed(self.app) and self.reinstall_app:
                    self.device.uninstall_app(self.app)
                    self.device.install_app(self.app, grant_runtime_permissions=True)
                elif not self.device.app_installed(self.app):
                    self.device.install_app(self.app, grant_runtime_permissions=True)


            logger.info("Starting session")

            try:
                #self.driver = webdriver.Remote(command_executor=appium_server_url, options=capabilities_options)
                capabilities_options = UiAutomator2Options().load_capabilities(desired_caps)
                self.appium_wd = webdriver.Remote(command_executor=self.command_executor, options=capabilities_options)

            except MaxRetryError as err:
                logger.critical("Could not connect to WDA command executor")
                raise err

            if self.app_starter is not None:
                self.app_starter.setup(desired_caps)
                self.app_starter.start()

            self.app_model = AndroidAppModel(session=self)

    def get_current_activity(self) -> str:
        return self.appium_wd.current_activity

    def stop(self) -> None:
        """Quits the running Appium session. Attempts to close app and return to home screen if using physical device or
        emulator is still running.
        """
        if hasattr(self, "appium_wd") and self.appium_wd:
            try:
                if not self.device.emulator or (
                    self.device.emulator and self.device.emulator.is_running()
                ):
                    logger.debug("Returning to device home screen")
                    #self.device.close_app(self.app.app_package)
                    self.device.close_all_apps(self.get_current_activity())
                    self.appium_wd.press_keycode(ANDROID_HOME_KEY_CODE)

                if self.app_starter is not None:
                    self.app_starter.stop()

                logger.info("Quitting Appium session")
                self.appium_wd.quit()
            except WebDriverException:
                logger.warning(
                    "Stopping session did not go gracefully: Appium raised WebDriverException", exc_info=True
                )

    def explore(
        self,
        explorer: Type[AndroidExplorationStrategy],
        benchmark: Type[ExplorationBenchmark],
        results_helper: StorageHelper.AnalysisResultsHelper,
        steps: int,
    ) -> None:
        """Explores the app automatically using the given Strategy, Benchmark and number of steps. Stores results with
        the help of StorageHelper. Starts the session if Appium is not running yet.

        Args:
            explorer: ExplorationStrategy handling actual app analysis and control.
            benchmark: ExplorationBenchmark analysing and measuring explorer behaviour.
            results_helper: AnalysisResultsHelper used to store exploration results and steps to disk.
            steps: Number of steps for which app should be explored.

        Raises:
            WebDriverException: If an unexpected error is encountered by Appium during exploration. Results are
                                stored nevertheless.
        """
        if not hasattr(self, "appium_wd"):
            logger.info("No Appium session found, starting new one.")
            self.start()

        # This should include the app itself
        processes_before_analysis = set(
            self.appium_wd.execute_script(
                "mobile: shell", {"command": "ps", "args": ["-A", "-o USER,CMDLINE"]}
            ).splitlines()
        )
        self.explorer = explorer(self)
        self.benchmark = benchmark(self)
        start = time.time()
        try:
            self.explorer.explore(results_helper=results_helper, steps=steps)
        except WebDriverException as err:
            # Re-raise error after storing results
            raise err
        finally:
            results_helper.store_analysis_stats(app=self.app,
                                                duration=time.time()-start,
                                                do_pcap_analysis=self.do_pcap_analysis
                                                )

        processes_after_analysis = set(
            self.appium_wd.execute_script(
                "mobile: shell", {"command": "ps", "args": ["-A", "-o USER,CMDLINE"]}
            ).splitlines()
        )

        processes_started_during_analysis = (
            processes_after_analysis - processes_before_analysis
        )
        processes_started_during_analysis_str = "\n    ".join(
            [
                proc
                for proc in processes_started_during_analysis
                if not proc.startswith("root")
            ]
        )
        if processes_started_during_analysis_str:
            logger.info(
                f"The following non-root processes were started during the analysis: "
                f"\n    {processes_started_during_analysis_str}"
            )
