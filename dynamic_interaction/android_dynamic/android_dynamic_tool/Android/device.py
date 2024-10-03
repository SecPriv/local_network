from __future__ import annotations

from logging import getLogger, Logger
import lzma
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import List, Optional, Tuple, Union
import urllib.request

from .emulator import AndroidEmulator
from .app import AndroidApp
from ..helper.constants import LOGGER_BASE_NAME, PATH_TO_ADB, TMP_ROOT

FRIDA_SERVER_VERSION = "16.1.7"
DEFAULT_REMOTE_BINARY_PATH = "/data/local/tmp/"

logger: Logger = getLogger(LOGGER_BASE_NAME + ".android.device")


class AndroidDevice:
    """Encapsulates information about an Android-based test device. The device may be physical or emulated."""

    name: str  # Emulator name - ignored by Appium
    avd_name: str  # Name of Android Virtual device to launch
    udid: str  # Must be specified as name is ignored for Android (seen when running `adb devices`)
    backup_path: Optional[Path]
    platform_version: str
    platform_name: str = "Android"
    emulator: Optional[AndroidEmulator]
    frida_remote_binary: Optional[str]
    architecture: Optional[str]
    downloads_path: Path

    def __init__(
            self,
            name: str,
            avd_name: str,
            udid: str,
            platform_version: str,
            backup_path: Optional[Path] = None,
            emulator: Optional[AndroidEmulator] = None,
            architecture: Optional[str] = None,
            downloads_path: Optional[Path] = None
    ) -> None:
        """Initializes AndroidDevice object.

            Args:
                name: Name of the device. Currently unused.
                avd_name: Name of the AVD, empty string if unknown.
                udid: UDID of the device as shown by ``adb devices``. Used to connect to device via Appium and adb.
                backup_path: Path to zip file containing backup of AVD.
                platform_version: Android version (e.g. 4.2 or 11)
                emulator: Emulator object if device is AVD.
                architecture: Device architecture (e.g., x86 or arm)
        """
        self.name = name
        self.avd_name = avd_name
        self.udid = udid
        self.backup_path = backup_path
        self.platform_version = platform_version
        self.emulator = emulator
        self.architecture = architecture
        self.downloads_path = downloads_path
        self.frida_remote_binary = None
        self.end_frida() 

        if self.downloads_path is None:
            self.downloads_path = Path(tempfile.mkdtemp())

    def issue_adb_command(
            self, arguments: List[str], timeout: int = 10, no_wait: bool = False
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Sends adb command to emulator and waits for response, takes care that correct emulator is reached.
        If subprocess is not finished after timeout seconds, it is killed and (None, stdout, stderr) is returned.
        If no_wait is True, the method always returns (None, None, None) and will not kill the subprocess.

        Args:
            arguments: List of arguments sent using adb. Do not include -s.
            timeout: Number of seconds allowed for the command to take before it is terminated.
                        Negative numbers lead to unexpected behavior. Ignored if no_wait is True.
            no_wait: Do not wait for process to be finished. Ignore timeout.
        Returns:
            Tuple of return_code, output to stdout and output to stderr
        """
        return_code: Optional[int] = None
        output: str = ""
        output_stderr: str = ""

        command_line: List[str] = [
                                      PATH_TO_ADB,
                                      "-s",
                                      self.udid,
                                  ] + arguments

        _logger: Logger = getLogger(logger.name + ".issue_adb_command")
        _logger.debug(f"Executing command: "f"{str(command_line)}""")

        if no_wait:
            subprocess.Popen(command_line)
            return None, None, None
        with subprocess.Popen(
                command_line,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
        ) as proc:
            try:
                output, output_stderr = proc.communicate(timeout=timeout)
                return_code = proc.poll()
            except subprocess.TimeoutExpired:
                proc.kill()
                _logger.debug(f"ADB command timeout ({timeout}): "f"{str(command_line)}""")
        return return_code, output, output_stderr

    def issue_adb_shell_command_with_root(
            self, shell_command: str, timeout: int = 10, no_wait: bool = False
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        if self.su_requires_argument_c():
            su_command_switch = "-c "
        else:
            su_command_switch = ""
        arguments = ["shell", f"su root {su_command_switch}{shell_command}"]
        return self.issue_adb_command(arguments, timeout=timeout, no_wait=no_wait)

    def is_connected(self) -> bool:
        return_code, output, output_stderr = self.issue_adb_command([
            "devices"
        ])
        if return_code != 0:
            raise RuntimeError("adb devices failed")

        device_regex = re.compile(r"^([\w-]+)\sdevice$", re.MULTILINE)
        output_lines = output.splitlines()
        for line in output_lines:
            match = device_regex.match(line)
            if match is not None:
                if match.group(1) == self.udid:
                    return True
        return False

    def extract_apk(self, pkg_name: str) -> Optional[Path]:
        _logger: Logger = getLogger(logger.name + ".extract_apk")
        file_handle, file_path = tempfile.mkstemp(dir=TMP_ROOT)
        return_code, output, output_stderr = self.issue_adb_command(
            [
                "shell",
                "pm",
                "path " + pkg_name + " | awk -F':' '{print $2}'",
            ],
        )

        # this solution discards al auxiliary apks (like split configs)
        paths = [path for path in output.splitlines(keepends=False) if path.endswith("base.apk")]

        if len(paths) > 1:
            _logger.error(f"More than one path available. ADB-Output: {output}")
            return None

        path_on_device = paths[0]

        return_code, output, output_stderr = self.issue_adb_command(
            ["pull", path_on_device, file_path]
        )
        if return_code != 0:
            _logger.error(f"ADB returned {return_code} ADB-Output: {output}")
            return None
        return Path(file_path)

    def _frida_file_path(self) -> Path:
        if self.architecture is None:
            self.detect_architecture()
        architecture_class = AndroidDevice.get_architecture_class(self.architecture)
        file_name = f"frida-server-{FRIDA_SERVER_VERSION}-android-{architecture_class}"
        file_path = Path(f"./{file_name}")
        return file_path

    def download_frida(self, overwrite: bool = False) -> None:
        destination_path = self._frida_file_path()
        print(destination_path)
        architecture_class = AndroidDevice.get_architecture_class(self.architecture)
        file_name = f"frida-server-{FRIDA_SERVER_VERSION}-android-{architecture_class}"
        if overwrite or not destination_path.is_file():
            link = f"https://github.com/frida/frida/releases/download/{FRIDA_SERVER_VERSION}/{file_name}.xz"
            logger.info(f"Downloading Frida server from {link}")
            data: bytes = urllib.request.urlopen(link).read()
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            decompressed_data: bytes = decompressor.decompress(data)
            with open(destination_path, "wb") as file:
                file.write(decompressed_data)

    def detect_architecture(self) -> str:
        return_code, architecture, output_stderr = self.issue_adb_command([
            "shell", "getprop ro.product.cpu.abi"
        ])
        if return_code == 0:
            self.architecture = architecture.strip()
            return self.architecture
        else:
            self.architecture = None
            raise RuntimeWarning("Can not detect device architecture by adb getprop. Return code: " + str(return_code))

    @staticmethod
    def get_architecture_class(architecture: str) -> str:
        # https://developer.android.com/ndk/guides/abis#sa
        if architecture == "armeabi-v7a":
            return "arm"
        if architecture == "arm64-v8a":
            return "arm64"
        if architecture == "x86":
            return "x86"
        if architecture == "x86_64":
            return "x86_64"
        else:
            raise ValueError("Invalid ABI.")

    def is_rooted(self) -> bool:
        if not self.is_connected():
            raise RuntimeError("Can not check root if device is not running and connected.")
        return_code, command_path, output_stderr = self.issue_adb_command([
            "shell", "command -v su"
        ])
        if return_code == 0:
            return True
        return False

    def su_requires_argument_c(self) -> bool:
        if not self.is_rooted():
            raise RuntimeError("su not available on non-rooted devices.")
        return_code, su_help, output_stderr = self.issue_adb_command([
            "shell", "su --help"
        ])
        if return_code == 0:
            su_c_argument_regex = re.compile(r'^\s*(-c)|(--comand),?\s+.*$')
            for line in su_help.splitlines():
                if su_c_argument_regex.match(line):
                    return True
            return False
        raise RuntimeError("Getting su help failed.")

    def shell_root_permission(self) -> bool:
        test_string = "root-test"
        logger.info("Verifying if the shell can run su. If the su permissions manager asks for root permission,"
                    " GRANT them PERMANENTLY")
        return_code, output, output_stderr = self.issue_adb_shell_command_with_root(f"echo {test_string}",
                                                                                    timeout=120)
        if return_code == 0 or output == test_string:
            return True
        else:
            logger.warning("Shell does not have root permissions. Please check the confirmation of the su permission"
                           " manager (e.g., Magisk Superuser)")
            return False

    def is_frida_running(self) -> bool:
        if not self.is_connected():
            raise RuntimeError("Device not connected")
        if self.frida_remote_binary is None:
            return False
        return_code, output, stderr = self.issue_adb_command(["shell", "ps -fA"])
        if return_code == 0:
            lines = output.splitlines()
            filename = os.path.basename(self.frida_remote_binary)
            return any(filename in line for line in lines)
        else:
            raise RuntimeError("ps over adb failed")

    def initialize_frida_server(self, destination_folder: Optional[Union[Path, str]] = None) -> None:
        _logger: Logger = getLogger(logger.name + ".initialize_frida_server")
        if not self.is_rooted():
            raise RuntimeError("Frida needs root permissions.")
        if not self.shell_root_permission():
            raise RuntimeError("shell needs root permissions."
                               " Please check the su permission manager (e.g., Magisk Superuser)")


        if self.is_frida_running():
            _logger.debug(f"On the remote device there is already a Frida server instance running;"
                          f" Not initializing Frida.")
            return
        self.download_frida()
        frida_binary_local = self._frida_file_path()
        if destination_folder is None:
            destination_folder = Path(DEFAULT_REMOTE_BINARY_PATH)
        elif isinstance(destination_folder, str):
            destination_folder = Path(destination_folder)
        destination_path = destination_folder / "frida-server"
        _logger.debug(f"Pushing {frida_binary_local} to {str(destination_path)} on remote device.")
        return_code, adb_output, output_stderr = self.issue_adb_command([
            "push",
            frida_binary_local,
            str(destination_path)
        ])
        if return_code != 0:
            raise RuntimeError("Pushing frida-server to Android device failed.")
        return_code, adb_output, output_stderr = self.issue_adb_command([
            "shell",
            f"chmod 775 \"{destination_path}\""
        ])
        if return_code != 0:
            logger.warning("Changing file permissions of frida-server on device failed (chmod).")
        self.frida_remote_binary = destination_path

        _logger.debug(f"Starting Frida server on remote device as root.")
        self.issue_adb_shell_command_with_root(str(destination_path) + " &", no_wait=True)
        time.sleep(1)
        # The Frida server needs a moment to start. Otherwise, a following connection to frida might fail.

    def app_installed(self, app: AndroidApp) -> bool:
        code, output, output_stderr = self.issue_adb_command(["shell", f"pm list packages {app.app_package}"])
        if f"package:{app.app_package}" in output:
            return True
        return False

    def get_split_files(self, app: AndroidApp) -> Set[str]:
        logger.info("Searching for split files")
        app_folder = os.path.dirname(app.apk_path)
        if app_folder == "":
            app_folder = "./"
        base_name = app.app_package + ".split."
        return set([os.path.join(app_folder,filename) for filename in os.listdir(app_folder) if filename.startswith(base_name)])


    def install_app(self, app: AndroidApp, grant_runtime_permissions: bool = True) -> None:
        logger.info(f"Installing {(app.name if app.name else app.apk_path.name)} on remote device.")
        split_files = self.get_split_files(app)
        print((split_files))
        if len(split_files) > 0:
            command = ["install-multiple"]
        else:
            command = ["install"]
        if grant_runtime_permissions:
            command += ["-g"]

        command += [str(app.apk_path)] + list(split_files)
        code, output, output_stderr = self.issue_adb_command(command, timeout=60)

        if code != 0:
            raise RuntimeError(f"Failed to install APK. Return code: {code}. Output: \"{output}\"."
                               f" Stderr output: \"{output_stderr}\".")

        for i in range(0,3):
            if self.app_installed(app):
                break
            else:
                time.sleep(10)

    def unlock_screen(self):
        self.issue_adb_command(["shell", "input", "keyevent", "82"]) #unlock screen - twice to be sure
        self.issue_adb_command(["shell", "input", "keyevent", "82"])#unlock screen

    def prepare_phone(self, mitmproxy_address):
        self.set_proxy(mitmproxy_address)
        self.issue_adb_command(["shell", "input", "keyevent", "164"])
        self.issue_adb_command(["shell", "settings", "put", "system", "screen_off_timeout", "6000000"])
        self.wait_if_internet_isnt_available(mitmproxy_address)


    def uninstall_3rd_party_apps(self):
        #copied from third eye
        _, packages,error = self.issue_adb_command(['shell', 'pm', 'list', 'packages', '-3', '|', 'cut' ,'-c9-', '|', 'grep', '-Ev', '"(io.appium.|com.apedroid.hwkeyboardhelperfree|com.github.shadowsocks|com.research.helper|org.proxydroid|com.fakemygps.android|org.meowcat.edxposed.manager|edu.berkeley.icsi.haystack|com.topjohnwu.magisk|app.greyshirts.sslcapture|tw.fatminmin.xposed.minminguard|com.cofface.ivader|com.emanuelef.remote_capture)"'])

        for package in packages.splitlines():
            logger.info(f"Uninstalling {package} from remote device.")
            self.issue_adb_command(["uninstall", package])

    def uninstall_app(self, app: AndroidApp) -> None:
        logger.info(f"Uninstalling {app.app_package} from remote device.")
        code, output, output_stderr = self.issue_adb_command(["uninstall", app.app_package])
        if code != 0:
            raise RuntimeError("Failed to uninstall app: " + output_stderr)

    def start_app(self, app: AndroidApp) -> None:
        logger.info(f"Start {app.app_package} if installed.")
        self.issue_adb_command(["shell", "monkey", "-p", app.app_package,  "1"])

    def stop_app(self, app: AndroidApp) -> None:
        logger.info(f"Stopping {app.app_package} if running.")
        code, output, output_stderr = self.issue_adb_command(["shell", "am", "force-stop", app.app_package])
        if code != 0:
            raise RuntimeError("Failed to stop app: " + output_stderr)

    def reset_app(self, app: AndroidApp) -> None:
        logger.info(f"Reset app {app.app_package} if installed.")
        code, output, output_stderr = self.issue_adb_command(["shell", "pm", "clear", app.app_package])
        if code != 0:
            raise RuntimeError("Failed to reset app: " + output_stderr)

    def upload_data(self, path: str, dest: str = "/sdcard/Download/"):
        code, output, output_stderr = self.issue_adb_command(["push", path, dest])
        if code != 0:
            raise RuntimeError("Failed to upload: " + path)


    def close_app(self, package: str):
        self.issue_adb_command(["shell", "pm", "clear", package])

    def get_paused_activites(self):
        return set(line.split()[3] for line in
                   self.issue_adb_command(["shell", "dumpsys", "activity", "activities", "|", "grep", "mLastPausedActivity"])[1].splitlines())

    def close_all_apps(self, current_activity = None):
        packages = self.get_paused_activites()
        print(f"paused packages: {packages}")
        if current_activity != None: # self.driver.current_activity()
            packages.add(current_activity)
        # packages.discard('com.android.launcher3/.lineage.LineageLauncher')
        packages.discard(
            'com.google.android.apps.nexuslauncher/.NexusLauncherActivity')
        packages.discard('com.google.android.apps.nexuslauncher/com.android.launcher3.settings.SettingsActivity')
        # packages.add('org.lineageos.jelly')
        # packages.add('com.android.chrome')
        for package in packages:
            p = package.split("/")[0]
            if p == "com.google.android.apps.nexuslauncher":
                self.issue_adb_command(["shell", "am", "force-stop",  p])
            elif self.issue_adb_command(["shell", "pm", "clear", p])[1] != "Success":
                return False
        return True


    def end_frida(self) -> None:
        self.issue_adb_shell_command_with_root('killall frida-server')


    def turn_on_wifi(self) -> None:
        self.issue_adb_command([ "shell", "svc", "wifi", "enable"])
        time.sleep(2)
        return

    def turn_off_wifi(self) -> None:
        self.issue_adb_command([ "shell", "svc", "wifi", "disable"])
        time.sleep(2)
        return

    def is_wifi_up(self) -> bool:
        _,output, _ = self.issue_adb_command(["shell", "dumpsys", "wifi"])
        return "Wi-Fi is enabled" in output



    def set_proxy(self,mitmproxy_address):
        if len(mitmproxy_address) > 0:
            logger.info(f"Set proxy to {mitmproxy_address}")
            _,output, _ = self.issue_adb_command(["shell", "settings", "put", "global", "http_proxy", mitmproxy_address])
        return

    def delete_proxy(self):
        _,output, _ = self.issue_adb_command(["shell", "settings", "put", "global", "http_proxy", ":0"])
        return

    def start_activity(self, package_name, activity) -> bool:
        _, output, error = self.issue_adb_command(["shell", "am", "start-activity", f"{package_name}/{activity}"])
        return error == None or len(error) == 0


    def start_tcpdump(self, app_package: str) -> bool:
        _, output, error = self.issue_adb_command(["shell", "am", "start", "-e", "action", "start", "-e", "pcap_dump_mode",
                                        "pcap_file", "-e", "app_filter", app_package, "-e",
                                        "pcap_name",
                                        f"{app_package}.pcap",
                                        "-e", "root_capture", "true",
                                        "-e", "capture_interface", "wlan0",  "-e", "auto_block_private_dns",
                                        "false", "-n",
                                        "com.emanuelef.remote_capture.debug/com.emanuelef.remote_capture.activities.CaptureCtrl"
                                        ])
        return error == None or len(error) == 0

    def stop_tcpdump(self, app_package: str, destination: str): # str(self.storage_helper.get_pcap_path(self.test_app))
        self.issue_adb_command(["shell", "am", "start", "-e", "action", "stop", "-n",
                "com.emanuelef.remote_capture.debug/com.emanuelef.remote_capture.activities.CaptureCtrl"])
        #time.sleep(1000)
        _, output, error =self.issue_adb_command(["pull", f"/sdcard/Download/PCAPdroid/{app_package}.pcap", destination])
        if error:
            print(error)
        self.issue_adb_command(["shell", "rm", f"/sdcard/Download/PCAPdroid/{app_package}.pcap"])

        return


    def is_internet_available(self):
        _, output, _ = self.issue_adb_command(["shell", "ping", "-c", "3", "1.1.1.1"])
        if "ttl=" in output:
            return True
        return False

    def wait_if_internet_isnt_available(self, mitmproxy_address):
        count = 0
        while self.is_internet_available() == False:
            print('Internet is not available, please wait')
            if self.is_wifi_up():
                self.turn_on_wifi()
                self.set_proxy(mitmproxy_address)
            else:
                #self.delete_proxy()
                self.turn_off_wifi()
                self.turn_on_wifi()
                self.set_proxy(mitmproxy_address)
            time.sleep(2)
            if count > 10:
                print("No Internet connection.")
                raise Exception
            count = count + 1

    def reboot_and_wait(self):
        self.issue_adb_command(["reboot"])
        time.sleep(30)
        self.unlock_screen()
        return


    #---------------TCP Dump-------------#
    def push_tcpdump(self):
        self.issue_adb_command(["push", "./tcpdump", "/system/bin/tcpdump"])
        self.issue_adb_command(["shell", "chmod", "755", "/system/bin/tcpdump"])
        os.remove("./tcpdump")


    def tcpdump_on_device(self) -> bool:
        _, output, _ = self.issue_adb_command(["shell", "ls", "/system/bin/"])
        return "tcpdump" in output


    def download_tcpdump(self) -> None:
        destination_path = "./tcpdump"
        if not os.path.exists(destination_path):
            link = f"https://www.androidtcpdump.com/download/4.99.4.1.10.4/tcpdump"
            print(f"Downloading tcpdump server from {link}")
            data: bytes = urllib.request.urlopen(link).read()
            with open(destination_path, "wb") as file:
                file.write(data)


    def init_tcpdump(self) -> None:
        if not self.tcpdump_on_device():
            self.download_tcpdump()
            self.push_tcpdump()


    def end_tcpdump(self):
        self.issue_adb_command(["shell", "su", "root", "-c", "killall", "tcpdump"])

    def start_tcpdump_on_phone(self, package):
        #self.shell("rm -f /sdcard/*")
        self.issue_adb_command(["shell", "rm", "-f", "/sdcard/Download/*.pcap"])
        self.init_tcpdump()

        self.end_tcpdump()

        _,output, error = self.issue_adb_command(
                [
                    "shell",
                    "su",
                    "root",
                    "-c",
                    "tcpdump",
                    "-i",
                    "wlan0",
                    "-w",
                    "/sdcard/Download/" + package + ".pcap", "&"
                ], timeout= 2
            )
        print(output)
        print(error)

    def stop_tcpdump_on_phone(self, package , destination):
        self.end_tcpdump()
        _, output, error  = self.issue_adb_command(["pull", "/sdcard/Download/" + package + ".pcap",destination])
        print(output)
        print(error)
