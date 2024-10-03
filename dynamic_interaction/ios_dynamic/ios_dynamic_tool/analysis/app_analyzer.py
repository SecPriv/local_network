from frida.core import Device, Session
import os
from datetime import datetime, timezone
import logging

import frida
import paramiko
import traceback

from .events.FridaEventHandler import FridaEventHandler, FridaEventHandlerQueue
from .constants import AccessTypes
from .model import Map
from .loggers import AnalysisReportWriter, NdJSONLogger

from .events.handlers.CameraInvocationHandler import CameraInvocationHandler
from .events.handlers.ContactsInvocationHandler import ContactsInvocationHandler
from .events.handlers.SimpleInvocationCounter import SimpleInvocationCounter
from .events.handlers.PhotosInvocationHandler import PhotosInvocationHandler
from .events.handlers.NetworkRequestHandler import NetworkRequestHandler
from .events.handlers.TrackingInvocationHandler import TrackingInvocationHandler
from .events.handlers.LocationInvocationHandler import LocationInvocationHandler
from .events.handlers.MicrophoneInvocationHandler import MicrophoneInvocationHandler

#######################################
# -- START CONFIG

LOGDEBUG = False

base_path = os.path.dirname(__file__) + '/'

assets_folder = base_path + 'assets/'
script_path = base_path + "frida_scripts/main.js"

# -- END CONFIG
#######################################


class AppAnalyzer:

    def __init__(self,
                 app_bundle_id: str,
                 analysis_output_folder_path: str,
                 device_uuid: str = "auto",
                 ):
        """
        device_udid can be 'auto' iff exactly one iOS device is connected via USB
        """
        self.pid: int = None
        self.frida_session: Session = None
        self.frida_device: Device = None
        self.session_start_datetime: datetime = None
        self.session_end_datetime: datetime = None

        self.app_bundle_id: str = app_bundle_id
        self.device_uuid = device_uuid
        self._eventHandlerQueue = FridaEventHandlerQueue()

        self.init_logging(analysis_output_folder_path)

    def init_logging(self, analysis_output_folder_path: str):
        now = datetime.now(tz=timezone.utc)
        filename_prefix = now.strftime("%Y%m%d_%H%M%S")
        if LOGDEBUG:
            filename_prefix = "_DEBUG"

        analysis_output_folder_path = analysis_output_folder_path + '/' + self.app_bundle_id

        self.eventLogger = NdJSONLogger(
            analysis_output_folder_path, filename_prefix)
        self.reporter = AnalysisReportWriter(
            analysis_output_folder_path, filename_prefix)

    def start_session(self):
        """
            Connect to device and launch target app
        """
        try:
            self.spawn_app_and_attach()
        except Exception as ex:
            logging.exception(
                f'failed to spawn and attach app with bundle id {self.app_bundle_id}, ending session.')
            raise ex

        # config before resuming app execution
        self.configure_script()
        self.init_event_handlers()
        self.configure_event_handlers_before_resume()

        self.session_start_datetime = datetime.now(tz=timezone.utc)
        self.reporter.update_analysis_info(
            'startTime', self.session_start_datetime.isoformat())

        # start app execution
        self.resume_app()

        # config after resuming app execution (some things only work afterwards)
        self.read_info_plist()
        self.configure_event_handlers_after_resume()

        self.run_static_analysis()

    def handle_event(self, message, binary_data):
        logging.debug(message)
        if message and 'payload' in message:
            event = Map(message['payload'])

            # frida_event = FridaEvent(event)
            self._eventHandlerQueue.handle_event(event)

            # create a backup of the analysis, in case it breaks during execution
            self.log_eventhandler_reports()

    def handle_external_event(self, event_name: str, event: dict):
        logging.debug(f'received external event {event_name}: {event}')
        self.eventLogger.log('external', event_name, event)

    def configure_script(self):
        with open(script_path) as scriptfile:
            scripttext = scriptfile.read()

        # create script
        self._script = self.frida_session.create_script(scripttext)

        self._script.on('message', self.handle_event)
        self._script.load()

    def init_event_handlers(self):
        self._simpleInvocationCounter = SimpleInvocationCounter()
        self._trackingHandler = TrackingInvocationHandler(self.eventLogger)
        self._networkHandler = NetworkRequestHandler(
            self.eventLogger, assets_folder)
        self._photosHandler = PhotosInvocationHandler(self.eventLogger)
        self._contactsHandler = ContactsInvocationHandler(self.eventLogger)
        self._locationHandler = LocationInvocationHandler(self.eventLogger)
        self._cameraHandler = CameraInvocationHandler(self.eventLogger)
        self._microphoneHandler = MicrophoneInvocationHandler(self.eventLogger)

        self._eventHandlerQueue.add(self._simpleInvocationCounter)
        self._eventHandlerQueue.add(self._trackingHandler)
        self._eventHandlerQueue.add(self._networkHandler)
        self._eventHandlerQueue.add(self._photosHandler)
        self._eventHandlerQueue.add(self._contactsHandler)
        self._eventHandlerQueue.add(self._locationHandler)
        self._eventHandlerQueue.add(self._cameraHandler)
        self._eventHandlerQueue.add(self._microphoneHandler)

    def configure_event_handlers_before_resume(self):
        """ Configure event handlers to be executed before the app analysis starts (before device.resume is called) """

        # could use separate scripts for individual trackers in the future
        self._trackingHandler.configure(self._script)
        self._photosHandler.configure(self._script)
        self._contactsHandler.configure(self._script)
        self._locationHandler.configure(self._script)
        self._cameraHandler.configure(self._script)
        self._microphoneHandler.configure(self._script)

    def spawn_app_and_attach(self):
        usb_devices = list(filter(lambda item: item.type ==
                                  'usb', frida.enumerate_devices()))

        if self.device_uuid == "auto":
            if len(usb_devices) > 1:
                logging.error(
                    "ERROR: More than one usb device connected - device uuid needs to be specified. (retrieve list with `idevice_id -l` or `ideviceinfo --simple`), exiting")
                exit(1)

            self.frida_device = frida.get_usb_device()

        else:
            logging.info(f'searching for device with UUID {self.device_uuid}')
            for available_device in usb_devices:
                if available_device.id == self.device_uuid:
                    self.frida_device = available_device
                    break

        if self.frida_device == None:
            logging.error("no device found, exiting")
            exit(1)

        logging.info(
            f'found usb device with UUID: {self.frida_device.id}')

        logging.info(f'spawning app with bundle id: {self.app_bundle_id}...')

        try:
            self.pid = self.frida_device.spawn(self.app_bundle_id)
        except Exception as ex:
            logging.exception('failed to spawn app - is it installed?')
            raise ex

        logging.info(f'attaching to app (pid: {self.pid})...')

        try:
            self.frida_session = self.frida_device.attach(self.pid)
        except frida.TimedOutError as ex:
            logging.exception('failed to attach - timeout. exiting')
            raise ex

        logging.info('successfully attached')

    def resume_app(self):
        """ RESUME APP EXECUTION. call this when config is complete, but don't wait too long, since iOS will otherwise kill app after a few seconds """

        logging.info("Resuming App Execution")

        self.frida_device.resume(self.pid)

    def configure_event_handlers_after_resume(self):
        """ Configure event handlers to be executed after the app analysis starts (before frida_device.resume is called).
            Some event handlers cannot be hooked before the app is resumed, so this is necessary (todo: find out why)
        """

        self._networkHandler.configure(self._script)

    def read_info_plist(self):
        """ Only works after app has been resumed """
        self.info_plist = self._script.exports.read_info_plist()

    def run_static_analysis(self):
        """ Do this after the app has been resumed """

        # extract app info from info.plist
        interesting_plist_fields = ['CFBundleDisplayName',
                                    'CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion']
        usage_descriptions = {}

        for key in self.info_plist.keys():
            if "UsageDescription" in key:
                usage_descriptions[key] = self.info_plist[key]

            if key in interesting_plist_fields:
                self.reporter.update_app_info(key, self.info_plist[key])

        self.reporter.update_app_info('usageDescriptions', usage_descriptions)

    def end_session(self):
        """ do reporting """
        logging.info('ending analysis session...')

        self.session_end_datetime = datetime.now(tz=timezone.utc)
        self.session_duration_seconds = int(
            (self.session_end_datetime-self.session_start_datetime).total_seconds())

        self.reporter.update_analysis_info(
            'endTime', self.session_end_datetime.isoformat())
        self.reporter.update_analysis_info(
            'duration_seconds', self.session_duration_seconds)

        try:
            self.log_eventhandler_reports()

            self._script.unload()
            self.frida_session.detach()
            self.frida_device.kill(self.pid)
        except Exception as e:
            logging.debug(f"could not close and clear event handler {e}")
        finally:
            try:
                self.eventLogger.close()
                self._eventHandlerQueue.clear()
            except Exception as e:
                logging.debug(f"could not close and clear event handler {e}")

        logging.info("analysis complete.")

    def log_eventhandler_reports(self):
        self.log_eventhandler_report(
            AccessTypes.Tracking, self._trackingHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Network, self._networkHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Photos, self._photosHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Contacts, self._contactsHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Location, self._locationHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Camera, self._cameraHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.Microphone, self._microphoneHandler, flush=False)
        self.log_eventhandler_report(
            AccessTypes.InvocationsSummary, self._simpleInvocationCounter, flush=False)

        try:
            self.reporter.flush()
        except:
            logging.exception('Failed to flush analysis report!')

    def log_eventhandler_report(self, type, handler: FridaEventHandler, flush: bool):
        try:
            report = self.get_eventhandler_report(handler)
            self.reporter.update_report(type, report, flush)
        except:
            logging.error(
                f'Failed to gather or write log for type: {type}, skipping')

    def get_eventhandler_report(self, handler: FridaEventHandler) -> dict:
        return handler.report(self.info_plist, {})


    def start_app_without_frida(self):
        """
        Requirement: 1. install Open on phone, 2. libusbmuxd on mac, 3. Phone connected via usb
        """
        host = "127.0.0.1"
        username = "root"
        password = "alpine"
        self.init_event_handlers()
        self.session_start_datetime = datetime.now(tz=timezone.utc)
        self.reporter.update_analysis_info(
            'startTime', self.session_start_datetime.isoformat())


        try:
            # Create SSH client
            ssh = paramiko.SSHClient()

            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            proxy_jump_command=f'inetcat 44  -u {self.device_uuid}'
            proxy = paramiko.ProxyCommand(proxy_jump_command)
            # Connect to the SSH server through the proxy
            ssh.connect(host, username=username, password=password, sock = proxy)
            # Now you can perform operations on the SSH connection as needed
            # For example, execute a command on the remote server
            _, _, stderr = ssh.exec_command(f"/var/jb/usr/bin/open {self.app_bundle_id}")
                # Print the output of the command
            error = stderr.read().decode()
            if len(error) > 0:
                if "inaccessible or not found" in error:
                    _, _, stderr = ssh.exec_command(f"/usr/bin/open {self.app_bundle_id}")
                    error = stderr.read().decode()
                    if len(error) > 0:
                        logging.exception(
                        f'Failed to start app: {error}')
                        raise RuntimeError("Open not available")

        except:
            logging.exception(f'Exception while starting the app via ssh: {traceback.format_exc()}')
            raise RuntimeError("SSH error")

        finally:
            # Close the SSH connection
            ssh.close()



# appBundleId = "com.apple.weather"
# appBundleId = "com.schiru.sorted"
# appBundleId = "com.apple.mobilesafari"
# appBundleId = "at.erstebank.george"
# appBundleId = "com.apple.AppStore"
# appBundleId = "com.schiru.SensitiveDataCollector"
# appBundleId = "at.gv.brz.wallet"
# appBundleId = "com.atebits.Tweetie2"
# appBundleId = "com.apple.Maps"
# appBundleId = "com.rovio.angrybirdsfriends"

# analyzer = AppAnalyzer(appBundleId)

# analyzer.start_session()

# # keep python script running - script will wait here
# # press CTRL-D (end of input) to continue running this script after this line
# sys.stdin.read()

# analyzer.end_session()
