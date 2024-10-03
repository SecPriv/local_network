# Module "fcntl" is available for Python 3.9 although PyCharm complaints it is not available.
# noinspection PyCompatibility
import fcntl
from logging import getLogger, Logger
import os
from pathlib import Path
from subprocess import PIPE, Popen, TimeoutExpired
from typing import IO, Optional

from objection.console.cli import cli, run
from scapy.all import PacketList, load_layer, sniff
from scapy.layers.tls.all import TLSAlert

from .ui_automator.exploration_session import AndroidExplorationSession
from .app import AndroidApp, AndroidAppStarter
from .device import AndroidDevice
from ..helper.constants import LOGGER_BASE_NAME

TLS_ALERT_BAD_CERTIFICATE = 42
TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43
TLS_ALERT_CERTIFICATE_UNKNOWN = 46
TLS_ALERT_UNKNOWN_CA = 48

OBJECTION_SSLPINNING_COMMAND = "android sslpinning disable"
OBJECTION_STARTUP_TIMEOUT = 10

logger: Logger = getLogger(LOGGER_BASE_NAME + ".certificate_pinning")


def count_possible_certificate_pinning_alerts(pcap_file: Path) -> int:
    load_layer("tls")
    # data: PacketList = rdpcap(str(pcap_file))
    data: PacketList = sniff(offline=str(pcap_file), lfilter=lambda x: x.haslayer(TLSAlert))
    # noinspection PyTypeChecker
    alert_messages: PacketList = data.getlayer(TLSAlert)
    certificate_pinning_alerts: PacketList = alert_messages.filter(scapy_filter_certificate_pinning_alert)
    return len(certificate_pinning_alerts)


def scapy_filter_certificate_pinning_alert(message: TLSAlert) -> bool:
    if isinstance(message, TLSAlert):
        return message.descr in (
            TLS_ALERT_BAD_CERTIFICATE,
            TLS_ALERT_UNSUPPORTED_CERTIFICATE,
            TLS_ALERT_CERTIFICATE_UNKNOWN,
            TLS_ALERT_UNKNOWN_CA
        )
    return False


def frida_objection_disable_sslpinning(device: AndroidDevice, app: AndroidApp) -> None:
    # run "objection -g PACKAGE.NAME run android sslpinning disable"
    cli(gadget=app.app_package, serial=device.udid)
    run(False, tuple(OBJECTION_SSLPINNING_COMMAND.split()))


def disable_certificate_pinning(device: AndroidDevice, app: AndroidApp) -> None:
    device.initialize_frida_server()
    frida_objection_disable_sslpinning(device, app)


class ObjectionAppStarter(AndroidAppStarter):
    objection_process = Optional[Popen]
    objection_command: Optional[str]

    OBJECTION_CONFIRMATION_OUTPUT = "Agent injected and responds ok!"

    def __init__(self, exploration_session: AndroidExplorationSession, objection_command: str) -> None:
        super().__init__(exploration_session)
        self.objection_command = objection_command

    @staticmethod
    def _non_block_read(output: IO) -> str:
        # https://gist.github.com/sebclaeys/1232088#file-non_blocking_read-py-L7
        fd = output.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # noinspection PyBroadException
        try:
            return str(output.read())
        except Exception:
            return ""

    @staticmethod
    def _process_join(process: Popen, time: int) -> None:
        try:
            process.wait(time)
        except TimeoutExpired:
            pass

    @staticmethod
    def _process_alive(process: Popen) -> bool:
        if process.poll() is not None:
            return False
        elif process.returncode is not None:
            return False
        else:
            return True

    def setup(self, desired_caps: dict) -> None:
        super().setup(desired_caps)
        self.exploration_session.device.initialize_frida_server()

    def start(self) -> None:
        objection_command = [
            "objection",
            "-g",
            self.exploration_session.app.app_package,
            "explore",
            "-s",
            self.objection_command
        ]
        logger.info(f"Trying to start app using objection.")
        logger.debug(f"Objection command: {str(objection_command)}")
        self.objection_process = Popen(objection_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        success = False
        for i in range(0, OBJECTION_STARTUP_TIMEOUT):
            if not self._process_alive(self.objection_process):
                raise RuntimeError("Starting objection failed.")
            self._process_join(self.objection_process, 1)
            output = self._non_block_read(self.objection_process.stdout)
            if self.OBJECTION_CONFIRMATION_OUTPUT in output:
                success = True
                break
        if not success:
            self.stop()
            raise RuntimeError("Objection didn't start successfully.")

    def stop(self) -> None:
        if isinstance(self.objection_process, Popen):
            logger.debug(f"Stopping objection.")
            if self._process_alive(self.objection_process):
                self.objection_process.stdin.write(b"exit\n")
                self.objection_process.stdin.flush()
                self._process_join(self.objection_process, 5)
                if self._process_alive(self.objection_process):
                    self.objection_process.terminate()
                    self._process_join(self.objection_process, 5)
                    if self._process_alive(self.objection_process):
                        self.objection_process.kill()
        if self.exploration_session.device.emulator is None:
            self.exploration_session.device.uninstall_app(self.exploration_session.app)
