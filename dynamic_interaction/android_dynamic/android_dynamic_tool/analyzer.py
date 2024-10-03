from __future__ import annotations

from io import TextIOBase
import logging
import os
from pathlib import Path
from subprocess import DEVNULL, Popen, STDOUT, TimeoutExpired
from typing import List, Optional, TextIO, Tuple, TypeVar, Union
import urllib3
import time


from selenium.common.exceptions import WebDriverException

from android_dynamic_tool.Android.app import AndroidApp, AndroidAppStarter
from android_dynamic_tool.Android.device import AndroidDevice
from android_dynamic_tool.Android.play_store import PlayStoreInstaller
from android_dynamic_tool.Android.ui_automator.exploration_session import AndroidExplorationSession
from android_dynamic_tool.Android.ui_automator.exploration_strategies import (
    AndroidExplorationStrategy,
    AndroidIntelligentRandomButtonExplorationStrategy,
    DFSStrategy
)
from android_dynamic_tool.Android.certificate_pinning import ObjectionAppStarter, OBJECTION_SSLPINNING_COMMAND
from android_dynamic_tool.common.exploration_benchmarks import ExplorationBenchmark, StepTimerExplorationBenchmark
from android_dynamic_tool.Android.frida import CONTENT_API_WATCH_LIST, DEFAULT_API_METHOD_WATCH_LIST, FridaAppStarter, \
    FridaCertificatePinningBypass, FridaClient, FridaContentAPICounter, FridaFileAccessTracker, FridaMethodCounter
from android_dynamic_tool.helper.constants import LOGGER_BASE_NAME
from android_dynamic_tool.helper import seeded_random
from android_dynamic_tool.helper.storage_helper import StorageHelper

LOCAL_LOGGER_BASE_NAME = LOGGER_BASE_NAME + ".analyzer"

APPIUM_STARTUP_TIMEOUT = 3

AndroidExplorationStrategyType = TypeVar('AndroidExplorationStrategyType', bound=AndroidExplorationStrategy)
ExplorationBenchmarkType = TypeVar('ExplorationBenchmarkType', bound=ExplorationBenchmark)


class Analyzer:
    appium_server: str  # Fully qualified address of the appium server
    appium_start_command: Optional[List[str]] = None  # command to start appium by analyzer. If None, analyzer expects
    # an already running appium instance (default behaviour)
    android_device: AndroidDevice  # Object holding all data of the test device
    storage_helper: StorageHelper  # StorageHelper object to help store all necessary data
    bypass_certificate_pinning: bool = False  # Try to bypass certificate pinning using Frida
    do_api_call_analysis: bool = False  # Indicates whether the tool shall analyse API calls made by the app.
    api_counting_list: Optional[List[Tuple[str, str]]] = None  # Overwrite the built-in list of API methods (class name,
    # method name) to watch for counting. If set to None, the tool will use the built-in default list. Ignored, if
    # do_api_call_analysis is set to False.
    content_api_list: Optional[List[Tuple[str, str]]] = None  # Overwrite the built-in list of Content API methods
    # (class name, method name) to watch for Content API access analysis (e.g., URI logging). If set to None,
    # the tool will use the built-in default list. Ignored, if do_api_call_analysis is set to False.
    use_objection: bool = False  # Use Objection instead of pure Frida. Support SSL Pinning Bypass only.
    steps: int = 25
    mitmproxy_address: str = ""
    create_pcap: bool = False
    capture_network_traffic_with_pcapdroid: bool = False
    pcapdroid_path: str = ""
    analyse_pcap: bool = False
    allow_reinstall_from: str = "NONE"
    grant_runtime_permissions: bool = True
    strategy = AndroidExplorationStrategyType = DFSStrategy # DFSStrategy
    benchmark = ExplorationBenchmarkType = StepTimerExplorationBenchmark
    text_input_list: Optional[List[str]] = None
    # If no app starter is set, an app starter is build based on the analysis config or Appium starts the app itself:
    app_starter: Optional[AndroidAppStarter] = None

    _logger: logging.Logger
    _started_appium_process: Optional[Popen] = None
    _appium_process_output: Optional[Union[TextIO, int]] = None
    cleaned: bool = None

    def __init__(self,
                 android_device: AndroidDevice,
                 storage_helper: StorageHelper,
                 appium_server: Optional[str] = None
                 ) -> None:
        """Initializes Analyzer object.

            Args:
                android_device: Object holding all data of the test device
                storage_helper: StorageHelper object to help store all necessary data
                appium_server: Fully qualified address of the appium server
        """
        self.appium_server = appium_server
        self.android_device = android_device
        self.storage_helper = storage_helper
        self._logger = logging.getLogger(LOGGER_BASE_NAME + ".Analyzer")

    def _prepare_analysis(self):
        seeded_random.reset_seeded_random()
        self.storage_helper.results.reset()
        self.android_device.close_all_apps()

    def _prepare_appium(self, app: Optional[AndroidApp] = None):
        if self.appium_start_command is not None:
            if self._appium_process_running():
                self.stop_appium()
            self.setup_appium(app=app)

    def _use_frida(self) -> bool:
        if not self.use_objection:
            if self.bypass_certificate_pinning or self.do_api_call_analysis:
                return True
        return False

    def _prepare_frida_client(self, exploration_session: AndroidExplorationSession) -> FridaClient:
        frida_client = FridaClient(exploration_session)
        frida_client.attach_to_running_process = False
        if self.bypass_certificate_pinning:
            frida_client.modules.append(FridaCertificatePinningBypass(frida_client))
        if self.do_api_call_analysis:
            counter_api_list = DEFAULT_API_METHOD_WATCH_LIST
            content_api_list = CONTENT_API_WATCH_LIST
            if self.api_counting_list:
                counter_api_list = self.api_counting_list
            if self.content_api_list:
                content_api_list = self.content_api_list
            for api in counter_api_list:
                counter = FridaMethodCounter(frida_client)
                counter.target_class, counter.target_method = api
                counter.storage_helper = self.storage_helper
                frida_client.modules.append(counter)
            for api in content_api_list:
                counter = FridaContentAPICounter(frida_client)
                counter.target_class, counter.target_method = api
                counter.storage_helper = self.storage_helper
                frida_client.modules.append(counter)
            file_access_tracker = FridaFileAccessTracker(frida_client, self.storage_helper)
            frida_client.modules.append(file_access_tracker)
        return frida_client

    def _build_app_starter(self, test_exploration_session: AndroidExplorationSession) -> Optional[AndroidAppStarter]:
        if self.app_starter:
            return self.app_starter
        if self.bypass_certificate_pinning and self.use_objection:
            app_starter = ObjectionAppStarter(test_exploration_session, OBJECTION_SSLPINNING_COMMAND)
            self._logger.debug(f'Using app starter "{app_starter.__class__.__name__} instead of letting Appium'
                               f' installing and starting app {test_exploration_session.app.apk_path.name}"')
            return app_starter
        if self._use_frida():
            app_starter = FridaAppStarter(test_exploration_session)
            app_starter.frida_client = self._prepare_frida_client(test_exploration_session)
            self._logger.debug(f'Using app starter "{app_starter.__class__.__name__} instead of letting Appium'
                               f' installing and starting app {test_exploration_session.app.apk_path.name}"')
            return app_starter
        return None

    def phase_without_interaction(self, seconds, test_app):
        self.android_device.install_app(test_app, grant_runtime_permissions=True)
        if self.capture_network_traffic_with_pcapdroid:
            self.android_device.start_tcpdump(test_app.app_package)
            self.android_device.start_tcpdump_on_phone(test_app.app_package)

        self.android_device.unlock_screen()
        self.android_device.start_app(test_app)

        time.sleep(seconds)

        if self.capture_network_traffic_with_pcapdroid:
            self.android_device.stop_tcpdump(test_app.app_package, str(self.storage_helper._get_app_dir(self.test_app)) + f"/{self.test_app.app_package}_1.pcap")
            self.android_device.stop_tcpdump_on_phone(test_app.app_package, str(self.storage_helper._get_app_dir(self.test_app)) + f"/tcpdump_{self.test_app.app_package}_1.pcap")
        self.android_device.stop_app(test_app)
        #self.android_device.uninstall_app(test_app)

    def analyze_apk_file(self, apk_path: Path) -> bool:
        """
        Installs and analyzes a given APK file.

        Args:
            apk_path: Path pointing to the APK file
        Returns:
            Analysis successful
        """
        self._prepare_analysis()

        temp_log_handler = self.storage_helper.logging.add_log_file_handler()

        self._logger.info(f'Starting analysis of "{apk_path}"')

        try_reinstall = False
        analysis_successful = False

        try:
            test_app = AndroidApp(apk_path)
            self.test_app = test_app
        except FileNotFoundError:
            self._logger.error(f'The file "{apk_path}" could not be found!')
            self.storage_helper.logging.close_log_file_handler(
                handler=temp_log_handler,
                android_app=None,
                prefix=f"{apk_path.name}-",
            )
            self.cleanup()
            return False
        self.android_device.prepare_phone(self.mitmproxy_address)
        self.android_device.uninstall_3rd_party_apps()

        self._prepare_appium(test_app)

        if test_app:
            test_app.install_source = "APK"

        self.storage_helper.store_metadata_and_apk(
            test_app,
            move_apk=False,  # Don't store apk in output dir to avoid removing it from the input dir or duplicating it
        )

        test_exploration_session = None

        try:
            if self.android_device.emulator:
                if self.create_pcap:
                    pcap_path = self.storage_helper.get_pcap_path(test_app)
                else:
                    pcap_path = ""

                self.android_device.emulator.start(pcap_path=str(pcap_path), mitmproxy_address=self.mitmproxy_address)

            if self.capture_network_traffic_with_pcapdroid:
                try:
                    pcapdroid_app: AndroidApp = AndroidApp(self.pcapdroid_path)
                except FileNotFoundError:
                    self._logger.error("PCAPDroid file not found")
                    self.cleanup()
                    return False

                if not self.android_device.app_installed(pcapdroid_app):
                    # add
                    self.android_device.install_app(pcapdroid_app)


            self._logger.info("No interaction phase started")
            self.phase_without_interaction(30, test_app)
            self._logger.info("No interaction phase ended, continue with interaction")


            self._logger.debug(f"Creating exploration session")
            test_exploration_session = AndroidExplorationSession(
                command_executor=self.appium_server,
                device=self.android_device,
                app=test_app,
                install_app_from_apk=True,
                reinstall_app=False
            )
            test_exploration_session.grant_runtime_permissions = self.grant_runtime_permissions
            test_exploration_session.do_pcap_analysis = self.analyse_pcap
            test_exploration_session.text_input_list = self.text_input_list
            test_exploration_session.capture_network_traffic_with_pcapdroid = self.capture_network_traffic_with_pcapdroid

            test_exploration_session.app_starter = self._build_app_starter(test_exploration_session)



            test_exploration_session.start()
            self._logger.info(
                f'Exploring app "{(test_app.name if test_app.name else test_app.apk_path.name)}"'
            )



            if self.capture_network_traffic_with_pcapdroid:
                self.android_device.start_tcpdump(test_app.app_package)
                self.android_device.start_tcpdump_on_phone(test_app.app_package)


            test_exploration_session.explore(
                explorer=self.strategy,
                benchmark=self.benchmark,
                results_helper=self.storage_helper.results,
                steps=self.steps,
            )
            self._logger.info(
                f'Finished exploring app "{(test_app.name if test_app.name else test_app.apk_path.name)}"'
            )
            analysis_successful = True

        except WebDriverException as err:
            self._logger.error(
                f'There was a "WebDriverException" while exploring the app '
                f'"{(test_app.name if test_app.name else test_app.apk_path.name)}"', exc_info=True
            )
            self.android_device.reboot_and_wait()
            if (
                    test_app.app_package
                    and f"Cannot start the '{test_app.app_package}' application." in err.msg
                    or "failed to install" in err.msg
            ):
                try_reinstall = True
                self._logger.info(
                    "The previous error indicates that there was an issue while starting/installing the application."
                )
                self._logger.info("Trying to reinstall app from App Store and analyse again")

        finally:
            if test_exploration_session:
                self._logger.info("Stopping exploration session")
                test_exploration_session.stop()
            if self.android_device.emulator and self.android_device.emulator.is_running():
                self.android_device.emulator.stop()
            self.cleanup()

            self.storage_helper.logging.close_log_file_handler(
                handler=temp_log_handler, android_app=test_app,
            )
            if try_reinstall:
                analysis_successful = self.analyze_app_package(package_name=test_app.app_package)

            self.cleanup()

        return analysis_successful

    def analyze_app_package(self, package_name: str, version_code: str = "") -> bool:
        """
        Installs and analyzes a given app package.

        Args:
            package_name: Package name of app, used to find app in store
            version_code: Version code of app, not available for installations from Google Play Store

        Returns:
            Analysis successful
        """
        self._prepare_analysis()

        temp_log_handler = self.storage_helper.logging.add_log_file_handler()

        if self.allow_reinstall_from == "NONE":
            self._logger.info("Reinstalling from app store is disallowed")
            self.cleanup()
            return False
        elif self.allow_reinstall_from == "GOOGLE_PLAY":
            self._logger.info(f'Starting analysis of "{package_name}" after installing from Google Play Store')
            if version_code:
                self._logger.warning("Version code is ignored, as Google Play Store does not support this")
        else:
            self._logger.error(f'Appstore "{self.allow_reinstall_from}" is unknown.')
            self.cleanup()
            return False

        analysis_successful = False

        try:
            if self.android_device.emulator:
                # Don't start from snapshot to improve speed of Google Play
                # Don't create PCAP or use MITMPROXY as installation should not be analyzed
                self.android_device.emulator.start(start_from_snapshot=False)
            installer = PlayStoreInstaller(self.android_device, self.appium_server)
            installed_app = installer.install_app_from_play_store(app_package=package_name)
        except RuntimeError:
            self._logger.exception("An unexpected error occurred while trying to install the app")
            installed_app = None
            analysis_successful = False

        if installed_app:
            self._prepare_appium(installed_app)
            if self.android_device.emulator:
                if self.create_pcap:
                    pcap_path = self.storage_helper.get_pcap_path(installed_app)
                else:
                    pcap_path = ""

                # Don't start from backup to preserve app previously installed
                self.android_device.emulator.restart_without_reset(
                    pcap_path=str(pcap_path),
                    mitmproxy_address=self.mitmproxy_address
                )
            self.storage_helper.store_metadata_and_apk(
                installed_app,
                move_apk=True,  # Store apk in output dir to avoid it being lost at cleaning of tempdir
            )

            test_exploration_session = None
            try:
                self._logger.debug(f"Creating exploration session")

                test_exploration_session = AndroidExplorationSession(
                    command_executor=self.appium_server,
                    device=self.android_device,
                    app=installed_app,
                    install_app_from_apk=False,
                )
                test_exploration_session.app_starter = self._build_app_starter(test_exploration_session)
                test_exploration_session.do_pcap_analysis = self.analyse_pcap
                test_exploration_session.text_input_list = self.text_input_list
                if test_exploration_session.app_starter:
                    test_exploration_session.app_starter.allow_app_installation = False
                test_exploration_session.start()
                self._logger.info(f'Exploring app "{installed_app.name}"')
                test_exploration_session.explore(
                    explorer=self.strategy,
                    benchmark=self.benchmark,
                    results_helper=self.storage_helper.results,
                    steps=self.steps,
                )
                self._logger.info(f'Finished exploring app "{installed_app.name}"')
                analysis_successful = True

            except WebDriverException:
                self._logger.exception(
                    f'There was a "WebDriverException" while exploring the app "{installed_app.name}"'
                )

            finally:
                if test_exploration_session:
                    self._logger.info("Stopping exploration session")
                    test_exploration_session.stop()
                if self.android_device.emulator and self.android_device.emulator.is_running():
                    self.android_device.emulator.stop()
                self.storage_helper.logging.close_log_file_handler(
                    handler=temp_log_handler,
                    android_app=installed_app,
                    prefix="install-from-store-",
                )
                self.cleanup()
                return analysis_successful
        else:
            if self.android_device.emulator:
                self.android_device.emulator.stop()
            self._logger.error(f"Installation failed")
            self.storage_helper.logging.close_log_file_handler(
                handler=temp_log_handler,
                android_app=None,
                prefix=f"{package_name}-failed-install-",
            )
            self.cleanup()
            return False

    def analyze_many_apk_files(self, apk_directory_path: Path) -> None:
        """
        Installs and analyzes APK files in a given directory.

        Args:
            apk_directory_path: Path pointing to a directory containing APK files
        """
        apk_paths = [
            apk_file for apk_file in apk_directory_path.glob("*.apk") if apk_file.is_file()
        ]

        self._logger.info(f"Starting analysis of {len(apk_paths)} Apps.")

        for i in range(len(apk_paths)):
            apk_path = apk_paths[i]
            try:
                self._logger.info(f"Start analyzing app {i + 1} of {len(apk_paths)}.")
                self.analyze_apk_file(apk_path)
            except RuntimeError:
                self._logger.exception(f"An unhandled exception occurred while analyzing {apk_path}")
        for apk_path in apk_paths:
            try:
                self.analyze_apk_file(apk_path)
            except RuntimeError:
                self._logger.exception(f"An unhandled exception occurred while analyzing {apk_path}")

    @staticmethod
    def build_default_appium_address(server: str, port: Union[int, str]) -> str:
        if isinstance(port, int):
            port = str(port)
        # noinspection HttpUrlsUsage
        return f"http://{server}:{port}/wd/hub" # FIXME: removed

    def setup_appium(self, app: Optional[AndroidApp] = None):
        if self.appium_start_command is not None:
            if self._started_appium_process is not None:
                self._started_appium_process.kill()
            if app is not None:
                self._appium_process_output = open(self.storage_helper.get_appium_log_path(app), mode='w')
            else:
                self._appium_process_output = DEVNULL

            self._started_appium_process = Popen(
                self.appium_start_command,
                env=os.environ,
                stdout=self._appium_process_output,
                stderr=STDOUT
            )
            #print(self.appium_start_command)
            for i in range(APPIUM_STARTUP_TIMEOUT):
                try:
                    self._started_appium_process.communicate(timeout=1)
                    return_code = self._started_appium_process.returncode
                    if return_code is not None:
                        raise RuntimeError(f"Could not start appium. Process exited with code {return_code}")
                except TimeoutExpired:
                    pass
                finally:
                    if self.check_appium_is_running():
                        return

    def stop_appium(self):
        if self._started_appium_process is not None:
            self._started_appium_process.kill()
            self._started_appium_process = None
            if isinstance(self._appium_process_output, TextIOBase):
                self._appium_process_output.close()
            self._appium_process_output = None

    def _appium_process_running(self) -> bool:
        if self._started_appium_process is None:
            return False
        self._started_appium_process.poll()
        if self._started_appium_process.returncode is not None:
            return False
        return True

    def test_appium(self) -> bool:
        started_by_test = False
        if self.appium_start_command is not None:
            if not self._appium_process_running():
                started_by_test = True
                self.setup_appium()
        check = self.check_appium_is_running()
        if self.appium_start_command is not None and not started_by_test:
            if self._appium_process_running():
                self.stop_appium()
                self.setup_appium()
                check = self.check_appium_is_running()
        if started_by_test:
            self.stop_appium()
        return check

    def check_appium_is_running(self) -> bool:
        if self.appium_server is None:
            raise RuntimeError("Appium server is undefined.")
        try:
            time.sleep(1)
            appium_status_code = (
                urllib3.PoolManager().request("GET", self.appium_server + "/sessions/").status
            )
            if appium_status_code != 200:
                if self.appium_start_command is None:
                    self._logger.critical(
                        f"Appium doesn't seem to be running; {self.appium_server}/sessions/"
                        f" returned HTTP status code {appium_status_code}"
                    )
                return False
        except urllib3.exceptions.MaxRetryError as e:
            self._logger.critical(
                f"Appium is not available, ensure that there is a running instance reachable at "
                f"{self.appium_server}"
            )
            return False
        return True

    def cleanup(self):
        print("cleanup")
        if self.capture_network_traffic_with_pcapdroid and not self.cleaned:
            self.android_device.stop_tcpdump(self.test_app.app_package, str(self.storage_helper._get_app_dir(self.test_app)) + f"/{self.test_app.app_package}_2.pcap")
            self.android_device.stop_tcpdump_on_phone(self.test_app.app_package, str(self.storage_helper._get_app_dir(self.test_app)) + f"/tcpdump_{self.test_app.app_package}_2.pcap")
            self.cleaned = True
        if self.appium_start_command is not None:
            self.stop_appium()

        self.android_device.end_frida()
