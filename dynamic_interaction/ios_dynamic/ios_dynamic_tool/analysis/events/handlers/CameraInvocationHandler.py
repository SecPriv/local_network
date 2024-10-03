import logging
from ...model import AudioVideoInvocationEvent, AudioVideoInvocationEventAccessType, FridaEvent
from ...constants import AccessTypes
from ...loggers import AnalysisEventLogger
from ...constants import FridaEventIdentifiers
from ..FridaEventHandler import FridaEventHandler


class CameraInvocationHandler(FridaEventHandler):
    def __init__(self, logger: AnalysisEventLogger) -> None:
        super().__init__(logger)

        self.configured = False
        self.libsIncluded = {
            "AVCaptureDevice": "check failed"
        }
        self.accessStatusChecked = False
        self.accessRequested = False
        self.requestCount = 0
        self.usage_description_key = "NSCameraUsageDescription"

        logging.info("listening for camera access...")

    def configure(self, script):
        self.configured = True

        if script.exports.hook_audio_video_direct() == True:
            self.libsIncluded["AVCaptureDevice"] = True

    def handle_event(self, event: FridaEvent):
        if event['name'] != FridaEventIdentifiers.AudioVideoInvocationEvent:
            return

        event: AudioVideoInvocationEvent = event

        if event['media_type'] != 'video':
            return

        if event['access_mode'] == 'status_check':
            logging.info('Camera access status checked')
            self.accessStatusChecked = True
            self.evtLogger.log(AccessTypes.Camera,
                               'access_status_checked', {'event': event})
        elif event['access_mode'] == 'access_request':
            logging.info('Camera access requested')
            self.accessRequested = True
            self.evtLogger.log(AccessTypes.Camera,
                               'access_requested', {'event': event})

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        if not self.configured:
            return "NOT CONFIGURED"

        requirementsDict = super().check_requirements(
            self.libsIncluded, info_plist, [self.usage_description_key])
        privacyLabelDict = super().check_privacy_label(
            app_store_info, 'USER_CONTENT', ['Photos or Videos', 'Fotos oder Videos'])

        return {
            "privacyLabel": privacyLabelDict,
            "accessStatusChecked": self.accessStatusChecked,
            "accessRequested": self.accessRequested,
            "requirements": requirementsDict,
            "metrics": {

            }
        }
