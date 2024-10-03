#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os.path
from pathlib import Path
from shlex import split
from signal import SIGINT, signal
import sys
from types import FrameType
from typing import Optional, Any

from android_dynamic_tool.analyzer import Analyzer
from android_dynamic_tool.Android.device import AndroidDevice
from android_dynamic_tool.Android.emulator import AndroidEmulator
from android_dynamic_tool.helper import seeded_random
from android_dynamic_tool.helper.constants import LOG_FORMATTER, LOGGER_BASE_NAME, EMULATOR_ANDROID_DEFAULT_LAUNCHER_PACKAGE_NAMES
from android_dynamic_tool.helper.helper_functions import check_path_exists, load_word_list
from android_dynamic_tool.helper.storage_helper import StorageHelper


def check_positive(value: Any) -> int:
    integer = int(value)
    if integer <= 0:
        raise argparse.ArgumentTypeError(f'{value} is an invalid positive int value')
    return integer


class AnalysisTool:

    def __init__(self,
                 apk_path: Path,
                 execution_details=None,
                 appium_start_command: str = None,
                 appium_server_address: str = 'localhost',
                 appium_server_port: int = 4723,
                 out_dir: Path = os.path.abspath("./out_dir"),
                 verbosity: str = 'DEBUG',
                 adb_udid: str = None,
                 virtual_device_name: str = None,
                 virtual_device_backup: Path = None,
                 wait_for_emulated_wifi: bool = False,
                 android_version: str = '11',
                 launcher_package_name: str = None,
                 steps: int = 25,
                 capture_network_traffic: bool = False,
                 capture_network_traffic_with_pcapdroid: bool = False,
                 pcapdroid_path:str = "",
                 mitmproxy_address: str = "",
                 allow_reinstall_from: str = 'NONE',
                 random_seed: str = None,
                 bypass_ssl_pinning: bool = False,
                 api_tracking: bool = False,
                 use_objection: bool = False,
                 no_grant_runtime_permissions: bool = False,
                 avd_gpu: str = None,
                 wordlist: str = None) -> None:

        self.execution_details = execution_details
        self.out_dir: Path = out_dir
        self.verbosity = verbosity
        self.virtual_device_backup = virtual_device_backup
        self.adb_udid = adb_udid
        self.wait_for_emulated_wifi = wait_for_emulated_wifi
        self.android_version = android_version
        self.avd_gpu = avd_gpu
        self.random_seed = random_seed
        self.virtual_device_name = virtual_device_name
        self.launcher_package_name = launcher_package_name
        self.steps = steps
        self.capture_network_traffic = capture_network_traffic
        self.capture_network_traffic_with_pcapdroid = capture_network_traffic_with_pcapdroid
        self.pcapdroid_path = pcapdroid_path
        self.mitmproxy_address = mitmproxy_address
        self.allow_reinstall_from = allow_reinstall_from
        self.bypass_ssl_pinning = bypass_ssl_pinning
        self.use_objection = use_objection
        self.api_tracking = api_tracking
        self.no_grant_runtime_permissions = no_grant_runtime_permissions
        self.appium_start_command = appium_start_command
        self.appium_server_address = appium_server_address
        self.appium_server_port = appium_server_port
        self.wordlist = wordlist
        self.apk_path = apk_path

    def _create_output_directory(self) -> Path:
        run_index = 0
        while Path(self.out_dir, f"run-{run_index:04d}").exists():
            run_index += 1
        output_directory: Path = Path(self.out_dir, f"run-{run_index:04d}")
        output_directory.mkdir(parents=True, exist_ok=False)
        return output_directory

    def _create_logger(self, output_directory: Path):
        logger = logging.getLogger(LOGGER_BASE_NAME)
        logger.setLevel(logging.DEBUG)

        # Create log handler for console output
        log_stream_handler = logging.StreamHandler(stream=sys.stdout)
        log_stream_handler.setFormatter(LOG_FORMATTER)
        log_stream_handler.setLevel(self.verbosity)
        logger.addHandler(log_stream_handler)

        logger.debug(f"Logging everything to: {output_directory / 'global_debug.log'}")
        global_debug_log_file_handler = logging.FileHandler(
            output_directory / "global_debug.log", mode="a"
        )
        global_debug_log_file_handler.setFormatter(LOG_FORMATTER)
        global_debug_log_file_handler.setLevel(logging.DEBUG)
        logger.addHandler(global_debug_log_file_handler)
        return logger

    def _create_app_analyzer(self, android_device: AndroidDevice, storage_helper: StorageHelper, appium):
        app_analyzer = Analyzer(
            android_device=android_device,
            storage_helper=storage_helper,
            appium_server=appium
        )
        app_analyzer.steps = self.steps
        app_analyzer.create_pcap = self.capture_network_traffic
        app_analyzer.capture_network_traffic_with_pcapdroid = self.capture_network_traffic_with_pcapdroid
        app_analyzer.pcapdroid_path = self.pcapdroid_path
        app_analyzer.mitmproxy_address = self.mitmproxy_address
        app_analyzer.allow_reinstall_from = self.allow_reinstall_from
        app_analyzer.bypass_certificate_pinning = self.bypass_ssl_pinning
        app_analyzer.use_objection = self.use_objection
        app_analyzer.do_api_call_analysis = self.api_tracking

        if not self.no_grant_runtime_permissions:
            app_analyzer.grant_runtime_permissions = True

        if self.appium_start_command:
            app_analyzer.appium_start_command = split(self.appium_start_command)

        if self.wordlist:
            app_analyzer.text_input_list = load_word_list(self.wordlist)

        return app_analyzer

    def start_analysis(self):

        # Create new and unique output-folder
        output_directory = self._create_output_directory()

        # Create logger
        logger = self._create_logger(output_directory)

        # Create StorageHelper object to enable storing of analysis results
        storage_helper = StorageHelper(
            output_dir=output_directory,
            base_logger=logger,
            log_level=self.verbosity,
            log_formatter=LOG_FORMATTER,
        )
        storage_helper.store_execution_details(self.execution_details)

        if self.random_seed:
            seeded_random.SEED = self.random_seed
        logger.info(f'Randomness is seeded with seed "{seeded_random.SEED}"')

        android_device = AndroidDevice(
            backup_path=self.virtual_device_backup,
            avd_name=(self.virtual_device_name if self.virtual_device_name else ""),
            name=self.adb_udid,
            udid=self.adb_udid,
            platform_version=self.android_version,
            downloads_path=storage_helper.get_downloads_path()
        )

        def cleanup(sig: int = -1, _: Optional[FrameType] = None) -> None:
            """Function used as signal-handler and for normal cleanup after the analysis is finished or crashed"""
            if sig == SIGINT:
                logger.info("SIGINT received - cleaning up and shutting down")
            else:
                logger.info("Cleaning up")
            if android_device.emulator:
                android_device.emulator.delete()

            android_device.delete_proxy()
            # Attempt to shut down logging trying to avoid a crash
            logging.shutdown()
            if sig == SIGINT:
                exit(1)

        signal(SIGINT, cleanup)
        try:
            if not android_device.name:
                logger.info("Preparing emulator for analysis")
                if self.launcher_package_name is None:
                    launcher = EMULATOR_ANDROID_DEFAULT_LAUNCHER_PACKAGE_NAMES[android_device.platform_version]
                else:
                    launcher = self.launcher_package_name
                android_device.emulator = AndroidEmulator(
                    avd_name=android_device.avd_name,
                    backup_path=android_device.backup_path,
                    wait_for_wifi=self.wait_for_emulated_wifi,
                    launcher_package_name=launcher
                )
                if self.avd_gpu:
                    android_device.emulator.gpu_option = self.avd_gpu
                android_device.name = android_device.emulator.emulator_name
                android_device.udid = android_device.emulator.emulator_name
            logger.info(f"Using device with udid {android_device.udid} for analysis")

            appium: Optional[str] = None
            if self.appium_server_address:
                appium = Analyzer.build_default_appium_address(self.appium_server_address, self.appium_server_port)

            # Create app analyzer
            app_analyzer = self._create_app_analyzer(android_device, storage_helper, appium)

            # Check if appium is running properly
            if not app_analyzer.test_appium():
                cleanup()
                exit(1)

            print(self.apk_path.is_file())
            # Start analysis
            if self.apk_path.is_file():
                logger.info("Starting analysis of single apk")
                app_analyzer.analyze_apk_file(self.apk_path)
            elif self.apk_path.is_dir():
                logger.info(f"Starting analysis of all APKs in {self.apk_path}")
                app_analyzer.analyze_many_apk_files(self.apk_path)
            else:
                logger.error(f"COULD NOT FIND THE FILE!!!")
            cleanup()
        except Exception as error:
            # If there is any unhandled exception, delete emulator and raise exception again
            try:
                if android_device.emulator:
                    cleanup()
                else:
                    android_device.reboot_and_wait()
            except Exception as error2:
                raise error2 from error
            raise error


def main() -> None:
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--appium-start-command",
        metavar="COMMAND",
        type=str,
        help="By default this program requires an already running appium server. If an appium start command is defined "
             "the program trys to start an appium server by itself (by executing the given command) for each app to "
             "analyze.",
    )
    parser.add_argument(
        "--appium-server-address",
        default="127.0.0.1",
        metavar="ADDRESS",
        type=str,
        help="The IP-address/domain of the appium server",
    )
    parser.add_argument(
        "--appium-server-port",
        default=4723,
        metavar="PORT",
        type=int,
        help="The port of the appium server",
    )
    parser.add_argument(
        "--out-dir",
        type=lambda p: Path(p).absolute(),
        default=Path("./out_dir/").absolute(),
        help="The location of the directory the logs and results should be written to. "
             "If omitted, './out_dir/' is used.",
    )
    levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    parser.add_argument(
        "--verbosity",
        default="DEBUG",
        metavar="LEVEL",
        type=str,
        choices=levels,
        help="Specify the verbosity for console output.",
    )
    android_device_group = parser.add_mutually_exclusive_group(required=True)
    android_device_group.add_argument(
        "--adb-udid",
        metavar="UDID",
        type=str,
        help="UDID of the running (physical or virtual) device as it shows up, when issuing the command `adb devices`.",
    )
    android_device_group.add_argument(
        "--virtual-device-name",
        metavar="NAME",
        type=str,
        help="Name of the stopped Android Virtual Device (AVD) as displayed by `emulator -list-avds`."
             "The device will be backed-up and a fresh instance will be started for each app.",
    )
    android_device_group.add_argument(
        "--virtual-device-backup",
        metavar="PATH",
        type=check_path_exists,
        help="Path to a zip file containing a full backup of an AVD (.avd folder and .ini file). "
             "If the AVD already exists, it will be overwritten. A fresh instance will be started for each app.",
    )
    parser.add_argument(
        "--wait-for-emulated-wifi",
        action='store_true',
        default=False,
        help="Wait for the emulated wifi to be in state CONNECTED/CONNECTED. "
             "NOTE: If emulated wifi is not connected after setup timeout, the analysis will continue with a warning."
    )
    parser.add_argument(
        "--android-version",
        metavar="VERSION",
        type=str,
        help="Android version of the test device.",
        required=True,
    )
    parser.add_argument(
        "--launcher-package-name",
        metavar="NAME",
        type=str,
        help="Package Name of the Android Launcher on the virtual device. By default the package name is guessed "
             "based on the defined Android version.",
    )
    analysis_options = parser.add_argument_group("Analysis Options", "Options to control analysis parameters")
    analysis_options.add_argument(
        "--steps",
        metavar="STEPS",
        type=check_positive,
        default=25,
        help="Set number of steps each analysis takes. Must be a positive integer."
    )
    analysis_options.add_argument(
        "--capture-network-traffic",
        action='store_true',
        default=False,
        help="Capture all network traffic generated during analysis. NOTE: This only works with emulators as of now. "
             "For all other setups, you have to do so by yourself."
    )
    analysis_options.add_argument(
        "--capture-network-traffic-with-pcapdroid",
        action='store_true',
        default=False,
        help="Capture all network traffic generated during analysis with pcapdroid."
    )
    analysis_options.add_argument(
        "--pcapdroid-path",
        type=str,
        default="./pcapDroid.apk",
        help="Capture all network traffic generated during analysis with pcapdroid."
    )
    analysis_options.add_argument(
        "--mitmproxy-address",
        metavar="ADDRESS",
        type=str,
        default="",
        help="Route all http(s) traffic through a mitmproxy server running at ADDRESS. By default mitmproxy listens at "
             "0.0.0.0:8080 if started. NOTE: This only works with emulators as of now."
    )
    app_stores = ("GOOGLE_PLAY", "NONE")
    analysis_options.add_argument(
        "--allow-reinstall-from",
        metavar="APPSTORE",
        type=str,
        default="NONE",
        choices=app_stores,
        help="Allow to reinstall for apps that cannot be installed from APK. \"NONE\" means that reinstall is "
             "disallowed. NOTE: The device has to be prepared for usage of this appstore."
    )
    analysis_options.add_argument(
        "--random-seed",
        metavar="SEED",
        type=str,
        default="",
        help="Set the seed for all randomness to SEED, if not set, it is randomly generated."
    )
    analysis_options.add_argument(
        "--bypass-ssl-pinning",
        action='store_true',
        default=False,
        help="Try bypassing SSL pinning using Frida (pure Frida or Objection tool)."
    )
    analysis_options.add_argument(
        "--api-tracking",
        action='store_true',
        default=False,
        help="Try to count several privacy-relevant API calls using Frida and a built-in method list."
    )
    analysis_options.add_argument(
        "--use-objection",
        action='store_true',
        default=False,
        help="Use Objection instead of pure Frida. Does not support API Call hooking."
    )
    analysis_options.add_argument(
        "--no-grant-runtime-permissions",
        action='store_true',
        default=False,
        help="Do not grant runtime permissions via adb install (by default runtime permissions are granted)."
    )
    analysis_options.add_argument(
        "--avd-gpu",
        metavar="OPTION",
        type=str,
        default="",
        help="Set a value for the -gpu option of the Android emulator."
    )
    analysis_options.add_argument(
        "--wordlist",
        metavar="FILE",
        type=str,
        default="",
        help="Set a wordlist to use random words instead of random strings for text input."
    )
    parser.add_argument(
        "apk_path",
        metavar="PATH",
        type=check_path_exists,
        help="Path to either a directory with APK files or a single APK file to be tested.",
    )

    args = parser.parse_args()

    if args.use_objection and args.api_tracking:
        parser.error("--api-tracking is not available while using Objection (--use-objection).")

    analysis_tool = AnalysisTool(
        execution_details=args,
        out_dir=args.out_dir,
        verbosity=args.verbosity,
        virtual_device_backup=args.virtual_device_backup,
        adb_udid=args.adb_udid,
        wait_for_emulated_wifi=args.wait_for_emulated_wifi,
        android_version=args.android_version,
        avd_gpu=args.avd_gpu,
        steps=args.steps,
        capture_network_traffic=args.capture_network_traffic,
        capture_network_traffic_with_pcapdroid=args.capture_network_traffic_with_pcapdroid,
        pcapdroid_path=args.pcapdroid_path,
        mitmproxy_address=args.mitmproxy_address,
        allow_reinstall_from=args.allow_reinstall_from,
        bypass_ssl_pinning=args.bypass_ssl_pinning,
        use_objection=args.use_objection,
        api_tracking=args.api_tracking,
        no_grant_runtime_permissions=args.no_grant_runtime_permissions,
        appium_start_command=args.appium_start_command,
        wordlist=args.wordlist,
        random_seed=args.random_seed,
        virtual_device_name=args.virtual_device_name,
        launcher_package_name=args.launcher_package_name,
        apk_path=args.apk_path,
        appium_server_port=args.appium_server_port
    )

    analysis_tool.start_analysis()


if __name__ == "__main__":
    main()
