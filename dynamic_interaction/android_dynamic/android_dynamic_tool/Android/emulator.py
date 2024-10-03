from __future__ import annotations

import logging
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Optional, Dict, Union
import zipfile

from ..helper.constants import (
    AVD_HOME_DIRECTORY,
    LOGGER_BASE_NAME,
    PATH_TO_ADB,
    PATH_TO_EMULATOR,
)


class AndroidEmulator:
    """
    Exposes all necessary interactions for controlling an AVD and emulator instance.
    """

    avd_name: str
    _path_to_backup: Optional[Path]
    _path_to_avd_dir: Path
    _path_to_avd_ini: Path
    _process: Optional[subprocess.Popen]
    _previous_start_kwargs: Dict[str, Union[str, int, None]] = dict()
    _port: int
    emulator_name: str
    # True = restore from backup and start, False = start without restoring from backup
    _start_from_backup: bool
    # True = restore & remove backup upon deletion of file object, False = remove avd dir and ini
    _restore_and_remove_backup: bool
    _logger: logging.Logger
    _complete_restore: bool = True
    wait_for_wifi: bool
    launcher_package_name: str = "com.android.launcher"
    gpu_option: Optional[str] = None

    def __init__(
        self,
        avd_name: Optional[str] = None,
        backup_path: Optional[Path] = None,
        port: int = 5580,
        wait_for_wifi: bool = False,
        launcher_package_name: Optional[str] = None
    ) -> None:
        """
        Set up emulator object for AVD specified by either avd_name or backup_path.
        Assumes that enough free space on disk is available.

        Args:
            avd_name: Name of an AVD as shown by ``emulator -list-avds``
            backup_path: Path to a zip file containing the backup of an AVD
            port: Port used as console port for the emulator instance. Must be even and between 5554 and 5584.
                  Other values may lead to unexpected behavior.
            wait_for_wifi: If True, wait for emulated Wi-Fi to be in state CONNECTED/CONNECTED.
            launcher_package_name: Android Launcher package name (default: com.android.launcher).
        """
        self._logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + f".android-emulator-{port}")
        if avd_name and backup_path:
            raise NotImplementedError("Only implemented for either avd_name or backup_path, not both.")

        if avd_name:
            self._start_from_backup = False
            self._restore_and_remove_backup = True
            self.avd_name = avd_name

            self._path_to_avd_dir = AVD_HOME_DIRECTORY / f"{self.avd_name}.avd"
            self._path_to_avd_ini = AVD_HOME_DIRECTORY / f"{self.avd_name}.ini"

            if not self._path_to_avd_dir.is_dir():
                raise FileNotFoundError(self._path_to_avd_dir)
            if not self._path_to_avd_ini.is_file():
                raise FileNotFoundError(self._path_to_avd_ini)

            self._path_to_backup = self._backup_avd()

        elif backup_path:
            self._start_from_backup = True
            self._restore_and_remove_backup = False
            if not backup_path.is_file():
                raise FileNotFoundError(backup_path)
            self._path_to_backup = backup_path
            self._logger.debug("Extracting avd_name from backup archive")
            with zipfile.ZipFile(self._path_to_backup, mode="r") as file:
                filename = [
                    file.name
                    for file in zipfile.Path(file).iterdir()
                    if file.name.endswith(".ini")
                ][0]
                self.avd_name = filename[: -len(".ini")]

            self._path_to_avd_dir = AVD_HOME_DIRECTORY / f"{self.avd_name}.avd"
            self._path_to_avd_ini = AVD_HOME_DIRECTORY / f"{self.avd_name}.ini"

        else:
            raise FileNotFoundError(
                "Either avd_name or backup_path have to be supplied."
            )

        self._process = None
        self._port = port
        self.emulator_name = f"emulator-{port}"
        self.wait_for_wifi = wait_for_wifi
        if launcher_package_name:
            self.launcher_package_name = launcher_package_name

    def delete(self) -> None:
        """
        Kill the emulator if running and restore state.

        If started from backup, .avd-folder and .ini are removed, else backup is restored and then removed.
        """
        self._logger.info("Deleting emulator instance")
        if self.is_running():
            self.stop()

        if self._restore_and_remove_backup and self._path_to_backup:
            self._logger.info("Restoring emulator instance and removing backup file")
            self._restore_avd(complete_restore=True)
            self._path_to_backup.unlink()
        else:
            self._logger.info(
                "Removing emulator files that have been extracted from backup"
            )
            self._path_to_avd_ini.unlink(missing_ok=True)
            if self._path_to_avd_dir.exists():
                shutil.rmtree(self._path_to_avd_dir)

    def _backup_avd(self) -> Path:
        """
        Backup AVD defined at object creation to unique zip-file.
        """
        def get_relative_path(root: Path, path: Path) -> Path:
            root_parts = [el for el in root.parts]
            path_parts = [el for el in path.parts]
            for part in root_parts:
                if path_parts[0] == part:
                    path_parts.pop(0)
                else:
                    break
            return Path(*path_parts)

        self._logger.info("Creating backup of AVD")

        _path_to_backup = Path(
            AVD_HOME_DIRECTORY,
            f"{time.strftime('%Y%m%dT%H-%M-%S', time.localtime())}_backup_{self.avd_name}.zip",
        )

        if _path_to_backup.exists():
            raise FileExistsError(_path_to_backup)

        with zipfile.ZipFile(
            _path_to_backup, mode="x", compression=zipfile.ZIP_DEFLATED
        ) as backup_file:
            for file in self._path_to_avd_dir.glob("**/*"):
                backup_file.write(
                    file, arcname=get_relative_path(AVD_HOME_DIRECTORY, file)
                )
            backup_file.write(
                self._path_to_avd_ini,
                arcname=get_relative_path(AVD_HOME_DIRECTORY, self._path_to_avd_ini),
            )

        self._logger.info("AVD-Backup finished")

        return _path_to_backup

    def _restore_avd(self, complete_restore: bool = True) -> None:
        """
        Restores AVD from backup in the quickest way possible.

        Args:
            complete_restore: If True, the potentially existing .avd-folder and .ini-file are removed and
                              overwritten, if False only the files that change during a run are removed and overwritten.
        """
        self._logger.info("Restoring AVD from backup")
        if not self._path_to_backup.is_file():
            raise FileNotFoundError(self._path_to_backup)

        if complete_restore:
            self._logger.debug("Starting a complete restore")
            self._logger.debug("Removing all old AVD files, if present")
            self._path_to_avd_ini.unlink(missing_ok=True)
            if self._path_to_avd_dir.exists():
                shutil.rmtree(self._path_to_avd_dir)

            self._logger.debug("Extracting files from backup")
            with zipfile.ZipFile(self._path_to_backup, mode="r") as backup_file:
                paths = [file.name for file in zipfile.Path(backup_file).iterdir()]
                for file in paths:
                    if (AVD_HOME_DIRECTORY / file).exists():
                        raise FileExistsError(file)
            with zipfile.ZipFile(self._path_to_backup, mode="r") as backup_file:
                backup_file.extractall(AVD_HOME_DIRECTORY)
        else:
            self._logger.debug(
                "Starting a shallow restore, only restoring those files that are normally changed "
                "and interfere with analysis."
            )
            self._logger.debug("Removing all old AVD files, if present")
            if self._path_to_avd_dir.exists():
                snapshot_dir = self._path_to_avd_dir / "snapshots"
                if snapshot_dir.exists():
                    shutil.rmtree(snapshot_dir)
                for file in self._path_to_avd_dir.iterdir():
                    if file.name.endswith(".qcow2") or file.name.endswith(".lock"):
                        file.unlink(missing_ok=True)

            self._logger.debug("Extracting removed files from backup")

            paths = zipfile.ZipFile(self._path_to_backup, mode="r").namelist()
            extract_paths = [
                path
                for path in paths
                if path.endswith(".qcow2") or path.endswith(".lock") or "/snapshots/" in path
            ]

            with zipfile.ZipFile(self._path_to_backup, mode="r") as backup_file:
                backup_file.extractall(AVD_HOME_DIRECTORY, members=extract_paths)

        if not self._path_to_avd_dir.is_dir():
            raise FileNotFoundError(self._path_to_avd_dir)
        if not self._path_to_avd_ini.is_file():
            raise FileNotFoundError(self._path_to_avd_ini)

        self._logger.info("Finished restoring AVD from backup")

    def start(
        self,
        pcap_path: Optional[str] = None,
        mitmproxy_address: Optional[str] = None,
        timeout: int = 40,
        start_from_snapshot: bool = True
    ) -> None:
        """
        Starts emulator after restoring it if necessary. Restarts emulator with the same options if already running.

        Args:
            pcap_path: If set, the emulator is instructed to dump all network traffic to a pcap file with this path.
            mitmproxy_address: If set, all HTTP(S) traffic from the emulator goes through this proxy.
            timeout: Time the emulator is given for startup in seconds. Defaults to 40 seconds.
                     Negative numbers may cause unexpected behavior.
            start_from_snapshot: If True, attempt to speed-up start of emulator by using snapshot,
                                 else forbid starting from snapshot. Defaults to True.
        """
        self._logger.info(f'Starting emulator with AVD "{self.avd_name}"')

        self._previous_start_kwargs = dict(
            pcap_path=pcap_path,
            mitmproxy_address=mitmproxy_address,
            timeout=timeout,
            start_from_snapshot=start_from_snapshot,
        )

        if self.is_running():
            self._logger.warning("This emulator is already running, restarting it!")
            return self._restart()

        if self._start_from_backup:
            # If we have to restore from backup initially, do a complete restore
            self._restore_avd(complete_restore=self._complete_restore)
            self._complete_restore = False
        else:
            # If we don't start from backup now, we have to do so after this start,
            # because the state of the AVD may change. (_start_from_backup may only be False for first start)
            self._start_from_backup = True

        command_line = [
            PATH_TO_EMULATOR,
            f"@{self.avd_name}",
            "-no-boot-anim",  # May speed up boot process
            "-port",  # Allows us to know port and therefore udid
            str(self._port),
        ]
        if self.gpu_option is not None:
            command_line.append("-gpu")
            command_line.append(self.gpu_option)
        if not start_from_snapshot:
            command_line.append("-no-snapshot-load")
        if pcap_path:
            self._logger.debug(
                f'tcpdump will store its pcap file at "{str(pcap_path)}"'
            )
            command_line.extend(["-tcpdump", pcap_path])
        if mitmproxy_address:
            self._logger.debug(
                f'All HTTP(S) traffic will be redirected through mitmproxy at "{mitmproxy_address}"'
            )
            # Start with writable-system to include the mitmproxy CA-Certificate
            command_line.extend(["-http-proxy", mitmproxy_address])

        self._logger.debug(f"Emulator start command: {str(command_line)}")

        # Set bufsize to 0 in order to be able to check output before the process has finished
        emulator_proc = subprocess.Popen(
            command_line,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        adb_proc = subprocess.Popen(
            [PATH_TO_ADB, "-s", self.emulator_name, "wait-for-device"]
        )

        start = time.time()
        started = False
        while not started:
            if emulator_proc.poll() is not None:
                self._logger.error(
                    f"Emulator process exited prematurely with exit code {emulator_proc.returncode}\n"
                    f"stdout: {emulator_proc.stdout.read()}\n\n"
                    f"stderr: {emulator_proc.stderr.read()}"
                )
                raise ChildProcessError
            if time.time() > start + timeout:
                self._logger.error(f"Emulator failed to start in {timeout} seconds.")
                self._process = emulator_proc
                raise TimeoutError

            if adb_proc.poll() == 0:
                with subprocess.Popen(
                    [
                        PATH_TO_ADB,
                        "-s",
                        self.emulator_name,
                        "shell",
                        f"ps | grep {self.launcher_package_name}",
                    ],
                    stdout=subprocess.PIPE,
                    text=True,
                ) as proc:
                    if self.launcher_package_name in proc.stdout.read():
                        time.sleep(3)  # Allow launcher to fully start
                        started = True

        self._logger.info(f"Emulator started successfully")
        self._process = emulator_proc

        if self.wait_for_wifi:
            self._logger.info(f"Waiting for emulated wifi to be in state CONNECTED/CONNECTED")

            while True:
                # check if connected
                with subprocess.Popen(
                    [
                        PATH_TO_ADB,
                        "-s",
                        self.emulator_name,
                        "shell",
                        f"dumpsys wifi | grep \"mNetworkInfo\"",
                    ],
                    stdout=subprocess.PIPE,
                    text=True,
                ) as proc:
                    if "CONNECTED/CONNECTED" in proc.stdout.read():
                        self._logger.info(f"Emulated wifi is in state CONNECTED/CONNECTED")
                        break

                if time.time() > start + timeout:
                    self._logger.warning(f"Emulated wifi failed to connect in {timeout} seconds."
                                         f"Proceeding without connected emulated wifi...")
                    break

    def stop(self) -> None:
        """
        Stops the emulator process by killing it. Does nothing, if it's not running.
        """
        if self.is_running():
            self._logger.debug("Killing emulator process")
            self._process.kill()
            # Otherwise the "emulator-crash-service" might remain as a "zombie" and prevent this script from exiting or
            # starting a new session.
            time.sleep(1)
            self._process.poll()
            self._process.kill()
        else:
            self._logger.debug("Emulator process has been killed already")
        self._process = None

    def _restart(self) -> None:
        """
        Stops the emulator process by killing it and restarts it with the same arguments as before.
        """
        self._logger.info("Restarting fresh emulator instance")
        self.stop()
        self.start(**self._previous_start_kwargs)

    def restart_without_reset(
        self,
        pcap_path: Optional[str] = None,
        mitmproxy_address: Optional[str] = None,
        timeout: int = 40,
        start_from_snapshot: bool = True,
    ) -> None:
        """
        Attempts to shut down the emulator gracefully and then restarts it without restoring the backup.
        Simply starts the emulator, if it's not running.

        Args:
            pcap_path: If set, the emulator is instructed to dump all network traffic to a pcap file with this path.
            mitmproxy_address: If set, all HTTP(S) traffic from the emulator goes through this proxy.
            timeout: Time the emulator is given for startup in seconds. Defaults to 40 seconds.
                     Negative numbers may cause unexpected behavior.
            start_from_snapshot: If True, attempt to speed-up start of emulator by using snapshot,
                                 else forbid starting from snapshot. Defaults to True.
        """
        self._logger.info("Restarting emulator without resetting state")

        if self.is_running():
            self._logger.debug("Sending SIGINT signal to emulator process")
            self._process.send_signal(signal.SIGINT)

            self._logger.debug("Waiting for emulator process to terminate")
            self._process.wait(20)
        else:
            self._logger.debug("Process has already been stopped")

        self._logger.debug("Starting emulator without restoring backup")
        self._start_from_backup = False
        self.start(
            pcap_path=pcap_path,
            mitmproxy_address=mitmproxy_address,
            timeout=timeout,
            start_from_snapshot=start_from_snapshot,
        )

    def is_running(self) -> bool:
        """
        Returns whether emulator is running.

        Returns:
            Emulator running
        """
        return self._process is not None and self._process.poll() is None
