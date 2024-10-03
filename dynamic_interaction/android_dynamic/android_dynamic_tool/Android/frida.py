"""Frida Module
This module implements the "client" functionality for hooking using Frida.
The required Frida server is set up by the corresponding methods in device.AndroidDevice.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from logging import getLogger, Logger
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

import frida
from frida.core import Device, Script, Session
from _frida import Application  # For typing only

from .app import AndroidApp, AndroidAppStarter
from .device import AndroidDevice
from .ui_automator.exploration_session import AndroidExplorationSession
from ..helper.constants import LOGGER_BASE_NAME
from ..helper.storage_helper import StorageHelper

FridaMessage = Tuple[str, int, str]

logger: Logger = getLogger(LOGGER_BASE_NAME + ".android.frida")
JS_MESSAGE_REGEX = r"\[([A-Z])\:([0-9]+)\] (.*)"
DEFAULT_API_METHOD_WATCH_LIST = [
    # Access to Advertising Id:
    # https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient
    ('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo'),
    ('android.telephony.TelephonyManager', 'getDeviceId'),  # IMEI / MEID
    ('android.telephony.TelephonyManager', 'getMeid'),  # MEID
    ('android.telephony.TelephonyManager', 'getNai'),  # NAI
    ('android.telephony.TelephonyManager', 'getSimSerialNumber'),  # SIM Card Serial Number
    ('android.telephony.TelephonyManager', 'getSubscriberId'),  # Usually the IMSI
    ('android.os.Build', 'getSerial'),  # Device Serial Number
    ('android.telephony.TelephonyManager', 'getServiceState'),  # Can contain location information
    ('android.location.LocationManager', 'addProximityAlert'),  # Location
    ('android.location.LocationManager', 'getCurrentLocation'),  # Location
    ('android.location.LocationManager', 'getLastKnownLocation'),  # Location
    ('android.location.LocationManager', 'requestLocationUpdates'),  # Location
    ('android.location.LocationManager', 'requestSingleUpdate'),  # Location
    ('android.media.MediaRecorder', 'setAudioSource'),  # Possible microphone access
    ('android.media.MediaRecorder', 'setCamera'),  # Possible camera access
    ('android.media.MediaRecorder', 'setVideoSource'),  # Possible camera access
    ('android.media.MediaRecorder', 'start'),  # Possible camera or microphone access
    ('android.media.AudioRecord', 'startRecording'),  # Microphone Access
    ('android.hardware.camera2.CameraManager', 'openCamera'),  # Camera access
    ('android.hardware.camera2.CameraCaptureSession', 'capture'),  # Camera access
    ('android.hardware.camera2.CameraDevice', 'createCaptureRequest'),  # Camera access
    ('android.hardware.camera2.CameraDevice', 'createCaptureSession'),  # Camera access
    ('android.hardware.camera2.CameraDevice', 'createCaptureSessionByOutputConfigurations'),  # Camera access
    ('android.hardware.camera2.CameraDevice', 'createReprocessableCaptureSession'),  # Camera access
    ('android.hardware.camera2.CameraDevice', 'createReprocessableCaptureSessionByConfigurations'),  # Camera access
    ('android.hardware.Camera', 'open'),  # Camera access (old Camera API)
    ('android.content.ClipboardManager', 'addPrimaryClipChangedListener'),  # Clipboard Read Access
    ('android.content.ClipboardManager', 'getPrimaryClip'),  # Clipboard Read Access
    ('android.content.ClipboardManager', 'getText'),  # Clipboard Read Access
    ('com.google.android.gms.location.FusedLocationProviderClient', 'getCurrentLocation'),  # Location
    ('com.google.android.gms.location.FusedLocationProviderClient', 'getLastLocation'),  # Location
    ('com.google.android.gms.location.FusedLocationProviderClient', 'requestLocationUpdates'),  # Location
    ('com.google.android.gms.location.LocationServices', 'getGeofencingClient'),  # Location
    #  ('java.io.File', '$init'),  # File Access (Constructor)
]
CONTENT_API_WATCH_LIST = [
    ('android.content.ContentResolver', 'bulkInsert'),
    ('android.content.ContentResolver', 'delete'),
    ('android.content.ContentResolver', 'insert'),
    ('android.content.ContentResolver', 'openAssetFile'),
    ('android.content.ContentResolver', 'openAssetFileDescriptor'),
    ('android.content.ContentResolver', 'openFile'),
    ('android.content.ContentResolver', 'openFileDescriptor'),
    ('android.content.ContentResolver', 'openInputStream'),
    ('android.content.ContentResolver', 'openOutputStream'),
    ('android.content.ContentResolver', 'openTypedAssetFile'),
    ('android.content.ContentResolver', 'openTypedAssetFileDescriptor'),
    ('android.content.ContentResolver', 'query'),
    ('android.content.ContentResolver', 'refresh'),
    ('android.content.ContentResolver', 'registerContentObserver'),
    ('android.content.ContentResolver', 'update'),
    ('android.content.context', 'getContentResolver'),
    ('android.content.ContentProviderClient', 'bulkInsert'),
    ('android.content.ContentProviderClient', 'delete'),
    ('android.content.ContentProviderClient', 'getStreamTypes'),
    ('android.content.ContentProviderClient', 'getType'),
    ('android.content.ContentProviderClient', 'insert'),
    ('android.content.ContentProviderClient', 'openAssetFile'),
    ('android.content.ContentProviderClient', 'openFile'),
    ('android.content.ContentProviderClient', 'openTypedAssetFile'),
    ('android.content.ContentProviderClient', 'openTypedAssetFileDescriptor'),
    ('android.content.ContentProviderClient', 'query'),
    ('android.content.ContentProviderClient', 'refresh'),
    ('android.content.ContentProviderClient', 'update'),
    ('android.content.ContentProviderOperation', 'newAssertQuery'),
    ('android.content.ContentProviderOperation', 'newCall'),
    ('android.content.ContentProviderOperation', 'newDelete'),
    ('android.content.ContentProviderOperation', 'newInsert'),
    ('android.content.ContentProviderOperation', 'newUpdate')
]
# Classes / methods hooked by the file access tracking module are defined in the corresponding JS file.


class FridaClient:
    exploration_session: AndroidExplorationSession
    modules: List[FridaModule] = []
    _frida_device: Device
    _frida_session: Optional[Session]
    _pid: Optional[int] = None
    # attach_to_running_process = True and spawn_process = True -> The tool will try to attach. If the app is not
    # running, it will spawn it.
    # attach_to_running_process = True and spawn_process = False -> The tool will try to attach. If the app is not
    # running, it will not spawn but fail.
    # attach_to_running_process = False and spawn_process = True -> The tool will always spawn a new process. If the app
    # is running, it will be restarted.
    # attach_to_running_process = False and spawn_process = False -> Illegal value
    attach_to_running_process: bool = False
    spawn_process: bool = True

    def __init__(self, exploration_session: AndroidExplorationSession) -> None:
        self.exploration_session = exploration_session
        self._frida_device = frida.get_device_matching(lambda d: d.id == self.get_android_device().udid)

    def get_android_device(self) -> AndroidDevice:
        return self.exploration_session.device

    def get_android_app(self) -> AndroidApp:
        return self.exploration_session.app

    def _load_modules(self) -> None:
        for module in self.modules:
            if module.frida_script is None:
                try:
                    module.frida_script = self._frida_session.create_script(module.get_frida_script())
                    module.frida_script.on('message', module.on_message)
                    module.frida_script.load()
                except frida.TransportError as err:
                    logger.error(f"Loading Frida module {module.__class__} failed ({err.__class__})."
                                 f" Continue analysis anyway.")

    def start(self) -> None:
        if not self.spawn_process and not self.attach_to_running_process:
            raise ValueError("spawn_process or attach_to_running_process needs to be True.")
        attached = False
        if self.attach_to_running_process:
            attached = self._try_attach()
        if self.spawn_process and not attached:
            self._spawn()
        time.sleep(1)
        self._load_modules()
        self._resume()

    def stop(self) -> None:
        for module in self.modules:
            if module.frida_script is not None:
                module.finalize()

    def _update_pid(self) -> None:
        self._pid = None
        app: Application
        for app in self._frida_device.enumerate_applications():
            if app.identifier == self.get_android_app().app_package:
                self._pid = app.pid
                break

    def _try_attach(self) -> bool:
        if self._pid is not None:
            self._frida_session = self._frida_device.attach(self._pid)
            if self._frida_session is None:
                logger.error(f"Attaching to {self._pid} ('{self.get_android_app().app_package}') failed.")
                return False
            else:
                return True
        else:
            logger.error(f"Attaching to {self._pid} ('{self.get_android_app().app_package}') failed. "
                         f"No process id is set.")
            return False

    def _spawn(self) -> None:
        old_pid = self._pid
        self._pid = self._frida_device.spawn([self.get_android_app().app_package])
        self._try_attach()
        if self._pid is None or self._frida_session is None or self._pid == old_pid:
            logger.error(f"Spawning '{self.get_android_app().app_package}' using Frida failed. No process id returned.")
            raise RuntimeError("Spawning using Frida failed")

    def _resume(self) -> None:
        if self._pid:
            self._frida_device.resume(self._pid)

    @staticmethod
    def parse_message(raw_message: str) -> FridaMessage:
        m = re.match(JS_MESSAGE_REGEX, raw_message)
        if not m:
            raise ValueError("Invalid message from client received")
        return m.group(1), int(m.group(2)), m.group(3)


class FridaModule(ABC):
    """Holds the data about a Frida module. A Frida module is the implementation of an arbitrary Frida-based approach.
    Mainly, it encapsulates a Frida script (JavaScript) and the functionality for communication with this script."""

    # frida_script Holds the frida.core.Script representation of an injected Script instance. It is set by the
    # FridaClient instance after injecting the script of this module.
    frida_script: Optional[Script] = None
    frida_client: FridaClient  # The FridaClient instance
    storage_helper: Optional[StorageHelper]  # An optional StorageHelper to store results

    def __init__(self, frida_client: FridaClient, storage_helper: Optional[StorageHelper] = None) -> None:
        """Initializes a new FridaModule instance.

        Args:
            frida_client: The Frida client to which this module shall belong.
            storage_helper: A StorageHelper to store results.
        """
        self.frida_client = frida_client
        self.storage_helper = storage_helper

    @abstractmethod
    def get_frida_script(self) -> str:
        """Returns the Frida script (JavaScript) as string.

        Returns:
            The JavaScript to inject
        """
        pass

    @abstractmethod
    def on_message(self, message: dict, data: Optional[bytearray]) -> None:
        """Handles messages from the injected script.

        Args:
            message: A dictionary containing metadata (e.g., 'type') and a textual message ('payload')
            data: Arbitrary binary data sent as an attachment. Can be None.
        """
        pass

    def finalize(self) -> None:
        """Performs tasks required after the exploration (e.g., stopping a service). Usually not required."""
        pass


class FridaAppStarter(AndroidAppStarter):
    """Uses a Frida client for an app initialization. Uninstalls an app after exploration from physical devices."""
    frida_client: Optional[FridaClient]  # The Frida client to use. Needs to be set before calling start().

    def setup(self, desired_caps: dict) -> None:
        """The setup routine required to be executed before the app can be started. Initializes the Frida server.

        Args:
            desired_caps: The Appium exploration session configuration (Desired Capabilities) used by the calling
                            exploration session.
        """
        super().setup(desired_caps)
        self.exploration_session.device.initialize_frida_server()

    def start(self) -> None:
        """Starts the app using the Frida client."""
        if self.frida_client is None:
            raise RuntimeError("frida_client needs to be set to start an app")
        self.frida_client.start()

    def stop(self) -> None:
        """Stops the Frida client and removes the app from a physical device."""
        self.frida_client.stop()
        if self.exploration_session.device.emulator is None:
            self.exploration_session.device.uninstall_app(self.exploration_session.app)


class FridaCertificatePinningBypass(FridaModule):
    """A Frida module to bypass certificate pinning using the Unpinning sciprt of the HTTP Toolkit project."""
    def get_frida_script(self) -> str:
        """Reads the JavaScript file for bypassing certificate pinning from the HTTP Toolkit project.
        The file is expected in the resources path of this package (resources/Frida-android-unpinning/frida-script.js)

        Returns:
            The Frida script as string
        """
        script_path = Path(__file__).parent / ".." / "resources" / "android-certificate-unpinning.js"
        with open(script_path, 'r') as file:
            return file.read()

    def on_message(self, message: dict, data: Optional[bytearray]) -> None:
        """This module does not expect any messages from the client."""
        pass  # No messages to parse from this script


class FridaMethodCounter(FridaModule):
    """A Frida module to count Android API calls."""
    target_class: str  # The target class
    target_method: str  # The target method. Can be "*" to capture calls to every method of the class.
    counter: int = 0  # The number of captured method calls.

    def get_full_method_name(self) -> str:
        """Builds the full method name containing beginning with the class name.

        Returns:
            The full method name.
        """
        return self.target_class + "." + self.target_method + "()"

    def get_frida_script(self) -> str:
        """Reads the JavaScript file for API call tracking and appends the correct run command.
        The file is expected in the resources path of this package (resources/frida_hook_android_function.js)

        Returns:
            The Frida script as string
        """
        script_path = Path(__file__).parent / ".." / "resources" / "frida_hook_android_function.js"
        file = open(script_path, 'r')
        code = file.read()
        file.close()
        code += f'run("{self.target_class}", "{self.target_method}");'
        return code

    def process_general_message(self, message: dict) -> Optional[FridaMessage]:
        """Processes general (log) messages (e.g., error messages) from Frida scripts defined in this tool.
        For messages containing information to be assessed by this tool (e.g., function return values), this function
        returns the parsed Frida message without further processing. Otherwise, it returns None.

        Args:
             message: Parsed Frida message (see FridaClient.parse_message())
        Returns:
             None in case of general (log) messages. Parsed Frida message otherwise (FridaMessage).
        """
        if message['type'] == "send":
            try:
                parsed_message = FridaClient.parse_message(message["payload"])
                if parsed_message[0] == "I":
                    logger.debug(f"Received debug message from JavaHookManager in Frida "
                                 f"(Module: {self.__class__}, Target: {self.get_full_method_name()}): "
                                 f"\"{parsed_message[2]}\"")
                    return None
                if parsed_message[0] in ("W", "E"):
                    logger.warning(f"Received {'warning' if parsed_message[0] == 'W' else 'error'} message "
                                   f"from JavaHookManager in Frida "
                                   f"(Module: {self.__class__}, Target: {self.get_full_method_name()}): "
                                   f"\"{parsed_message[2]}\"")
                    return None
                return parsed_message
            except ValueError:
                logger.error(f"Received not parsable message from JavaHookManager in Frida "
                             f"(Module: {self.__class__}, Target: {self.get_full_method_name()}): "
                             f"\"{str(message)}\"")
                return None
        if message['type'] == 'error':
            logger.error(f"Received error message from Frida "
                         f"(Module: {self.__class__}, Target: {self.get_full_method_name()}): "
                         f"\"{message['description']}\"; "
                         f"Stack: \"{message['stack']}\"")
        else:
            logger.debug(f"Received message of unknown type from Frida: {str(message)}")
        return None

    def on_message(self, message: dict, data: Optional[bytearray]) -> None:
        """Handles messages from the injected script.
        Messages have the format "[X:x] Message". Thereby, "X" is the information class:
            H: Hook-related message, e.g., a captured method call.
            I: Debug Information
            E: Error
            W: Warning
        "x" is an integer indicating the more concrete information class (e.g., H:1 for captured method call)
        The format of "Message" depends on the actual information type.

        Args:
            message: A dictionary containing metadata (e.g., 'type') and a textual message ('payload')
            data: Arbitrary binary data sent as an attachment. Can be None.
        """
        message_to_process: FridaMessage = self.process_general_message(message)
        if message_to_process:
            if message_to_process[0] == "H":
                if message_to_process[1] == 1:
                    self.counter += 1
                    logger.debug(f"Method called: {self.get_full_method_name()}. Counter: {self.counter}")
                    if self.storage_helper:
                        self.storage_helper.results.stats.api_calls[self.get_full_method_name()] = self.counter
                else:
                    logger.debug(f"Received hook message from JavaHookManager in Frida "
                                 f"(Module: {self.__class__}, Target: {self.get_full_method_name()}): "
                                 f"\"{message['payload']}\"")


class FridaContentAPICounter(FridaMethodCounter):
    """A Frida module to count Android API calls and Content API URIs passed to the called method as an argument."""
    uri_requests: Dict = dict()  # Dictionary for the results. Remains empty if a StorageHelper is assigned.

    def on_message(self, message: dict, data: Optional[bytearray]) -> None:
        """Handles messages from the injected script.
        Messages have the format "[X:x] Message". Thereby, "X" is the information class:
            H: Hook-related message, e.g., a captured method call.
            I: Debug Information
            E: Error
            W: Warning
        "x" is an integer indicating the more concrete information class (e.g., H:1 for captured method call)
        The format of "Message" depends on the actual information type.

        Args:
            message: A dictionary containing metadata (e.g., 'type') and a textual message ('payload')
            data: Arbitrary binary data sent as an attachment. Can be None.
        """
        super().on_message(message, data)
        if message['type'] == "send":
            try:
                parsed_message: FridaMessage = FridaClient.parse_message(message["payload"])
                if parsed_message:
                    if parsed_message[0] == "H" and parsed_message[1] == 4:
                        if parsed_message[2].startswith("URI: "):
                            uri: str = parsed_message[2][5:]
                            method = self.get_full_method_name()
                            result_dict = self.uri_requests
                            if self.storage_helper:
                                if method not in self.storage_helper.results.stats.content_uri_requests.keys():
                                    self.storage_helper.results.stats.content_uri_requests[method] = {}
                                result_dict = self.storage_helper.results.stats.content_uri_requests[method]
                            result_dict[uri] = result_dict.get(uri, 0) + 1
            except ValueError:
                pass


class FridaFileAccessTracker(FridaModule):
    """A Frida module to track file access via the Android API."""
    file_access_log = dict()  # Results dictionary: class -> {method -> {file -> counter}}

    def __init__(self, frida_client: FridaClient, storage_helper: Optional[StorageHelper] = None) -> None:
        """Initializes a new FridaFileAccessTracker instance.

        Args:
            frida_client: The Frida client to which this module shall belong.
            storage_helper: A StorageHelper to store results.
        """
        super().__init__(frida_client, storage_helper)
        if self.storage_helper:
            self.file_access_log = self.storage_helper.results.stats.file_access_log

    def get_frida_script(self) -> str:
        """Reads the JavaScript file for API call tracking.
        The file is expected in the resources path of this package (resources/frida_trace_file_access.js)

        Returns:
            The Frida script as string
        """
        script_path = Path(__file__).parent / ".." / "resources" / "frida_trace_file_access.js"
        file = open(script_path, 'r')
        code = file.read()
        file.close()
        return code

    def process_general_message(self, message: dict) -> Optional[FridaMessage]:
        """Processes general (log) messages (e.g., error messages) from Frida scripts defined in this tool.
        For messages containing information to be assessed by this tool (e.g., function return values), this function
        returns the parsed Frida message without further processing. Otherwise, it returns None.

        Args:
             message: Parsed Frida message (see FridaClient.parse_message())
        Returns:
             None in case of general (log) messages. Parsed Frida message otherwise (FridaMessage).
        """
        if message['type'] == "send":
            try:
                parsed_message = FridaClient.parse_message(message["payload"])
                if parsed_message[0] == "I":
                    logger.debug(f"Received debug message from File Access Tracking Script in Frida "
                                 f"(Module: {self.__class__}): "
                                 f"\"{parsed_message[2]}\"")
                    return None
                if parsed_message[0] in ("W", "E"):
                    logger.warning(f"Received {'warning' if parsed_message[0] == 'W' else 'error'} message "
                                   f"from File Access Tracking Script in Frida "
                                   f"(Module: {self.__class__}): "
                                   f"\"{parsed_message[2]}\"")
                    return None
                return parsed_message
            except ValueError:
                logger.error(f"Received not parsable message from File Access Tracking Script in Frida "
                             f"(Module: {self.__class__}): "
                             f"\"{str(message)}\"")
                return None
        if message['type'] == 'error':
            logger.error(f"Received error message from Frida "
                         f"(Module: {self.__class__}): "
                         f"\"{message['description']}\"; "
                         f"Stack: \"{message['stack']}\"")
        else:
            logger.debug(f"Received message of unknown type from Frida: {str(message)}")
        return None

    def on_message(self, message: dict, data: Optional[bytearray]) -> None:
        """Handles messages from the injected script.
        Messages have the format "[X:x] Message". Thereby, "X" is the information class:
            H: Hook-related message, e.g., a captured method call.
            I: Debug Information
            E: Error
            W: Warning
        "x" is an integer indicating the more concrete information class (e.g., H:5 for captured file access by a class
         constructor). The format of "Message" depends on the actual information type.

        Args:
            message: A dictionary containing metadata (e.g., 'type') and a textual message ('payload')
            data: Arbitrary binary data sent as an attachment. Can be None.
        """
        parsed_message: FridaMessage = self.process_general_message(message)
        if parsed_message:
            if parsed_message[0] == "H" and parsed_message[1] in (5, 6, 7):
                values = parsed_message[2].split(": ", 2)
                class_name = values[0]
                if parsed_message[1] == 5:
                    if "." in class_name:
                        method_name = class_name[class_name.rindex(".")+1:]
                    else:
                        method_name = class_name
                    file_path = values[1]
                else:
                    method_name = values[1]
                    file_path = values[2]
                if class_name not in self.file_access_log.keys():
                    self.file_access_log[class_name] = dict()
                if method_name not in self.file_access_log[class_name].keys():
                    self.file_access_log[class_name][method_name] = dict()
                self.file_access_log[class_name][method_name][file_path] \
                    = self.file_access_log[class_name][method_name].get(file_path, 0) + 1
