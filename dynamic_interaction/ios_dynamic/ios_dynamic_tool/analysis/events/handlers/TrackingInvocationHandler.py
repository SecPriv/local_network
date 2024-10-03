import logging
from ...constants import AccessTypes
from ...loggers import AnalysisEventLogger
from ...constants import FridaEventIdentifiers
from ...model import FridaEvent
from ..FridaEventHandler import FridaEventHandler


class TrackingInvocationHandler(FridaEventHandler):

    def __init__(self, logger: AnalysisEventLogger) -> None:
        super().__init__(logger)

        self.configured = False
        self.libsIncluded = {
            "ATTrackingManager": "check failed",
            "ASIdentifierManager": "check failed"
        }
        self.requestCount = 0
        self.accessStatusChecked = False
        self.accessRequested = False
        self.usage_description_key = "NSUserTrackingUsageDescription"

        logging.info("listening for ATT...")

    def configure(self, script):
        self.configured = True

        try:
            script.exports.hook_class_method(
                'ASIdentifierManager', "- advertisingIdentifier")

            self.libsIncluded["ASIdentifierManager"] = True
        except:
            logging.exception("hooking ASIdentifierManager failed")
            self.libsIncluded["ASIdentifierManager"] = False

        try:
            script.exports.hook_class_method(
                "ATTrackingManager", "+ trackingAuthorizationStatus")

            script.exports.hook_class_method(
                "ATTrackingManager", "+ requestTrackingAuthorizationWithCompletionHandler:")

            # deprecated in iOS 14, replaced by ATTrackingManager (may be removed in future iOS versions)
            script.exports.hook_class_method(
                "ASIdentifierManager", "- isAdvertisingTrackingEnabled")

            self.libsIncluded["ATTrackingManager"] = True
        except:
            logging.error(
                "hooking ATTrackingManager or ASIdentifierManager failed")
            self.libsIncluded["ATTrackingManager"] = False

    def handle_event(self, event: FridaEvent):
        if event['name'] != FridaEventIdentifiers.InvocationEvent:
            return

        # access if advertisingIdentifier
        if event['className'] == "ASIdentifierManager" and 'advertisingIdentifier'.lower() in event['methodName'].lower():
            logging.info("ATT requested")
            self.requestCount += 1
            self.evtLogger.log(AccessTypes.Tracking,
                               'advertising_identifier_requested', {'event': event})
            return

        # access status check
        if (event['className'] == "ASIdentifierManager" and 'isAdvertisingTrackingEnabled'.lower() in event['methodName'].lower()) or \
           (event['className'] == "ATTrackingManager" and 'trackingAuthorizationStatus'.lower() in event['methodName'].lower()):
            self.accessStatusChecked = True
            self.evtLogger.log(AccessTypes.Tracking,
                               'access_status_checked', {'event': event})
            return

        # access request
        if event['className'] == "ATTrackingManager" and "requestTrackingAuthorization".lower() in event['methodName'].lower():
            self.accessRequested = True
            self.evtLogger.log(AccessTypes.Tracking,
                               'access_requested', {'event': event})
            return

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        if not self.configured:
            return "NOT CONFIGURED"

        requirementsDict = super().check_requirements(
            self.libsIncluded, info_plist, [self.usage_description_key])
        privacyLabelDict = super().check_privacy_label(
            app_store_info, 'IDENTIFIERS', ['Device ID', 'Ger\u00e4te-ID'])

        return {
            "privacyLabel": privacyLabelDict,
            "accessStatusChecked": self.accessStatusChecked,
            "accessRequested": self.accessRequested,
            "requirements": requirementsDict,
            "metrics": {
                "advertisingIdentifierAccessed": self.requestCount > 0,
                "advertisingIdentifierAccessCount": self.requestCount
            }
        }
