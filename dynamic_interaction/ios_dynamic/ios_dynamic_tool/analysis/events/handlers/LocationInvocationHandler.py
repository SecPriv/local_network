import logging
from ...constants import AccessTypes
from ...constants import FridaEventIdentifiers
from ...loggers import AnalysisEventLogger
from ...model import FridaEvent
from ..FridaEventHandler import FridaEventHandler


class LocationInvocationHandlerMethods:
    auth_methods = [
        "- requestAlwaysAuthorization",
        "- requestWhenInUseAuthorization",
        "- requestTemporaryPreciseLocationAuthorizationWithPurposeKey:",  # optional
        "- requestTemporaryPreciseLocationAuthorizationWithPurposeKey:completion:",  # optional
        "- requestTemporaryFullAccuracyAuthorizationWithPurposeKey:",  # optional
        "- requestTemporaryFullAccuracyAuthorizationWithPurposeKey:completion:",  # optional
    ]

    location_request_methods = [
        "- requestLocation",
        "- location"  # last known location
    ]

    location_monitoring_methods = [
        "- startMonitoringForRegion:",
        "- startUpdatingHeading",
        "- startRangingFromPeers:",
        "- startUpdatingLocation",
        "- startUpdatingVehicleSpeed",
        "- startMonitoringSignificantLocationChanges",
        "- startUpdatingVehicleHeading",
        "- startRangingBeaconsSatisfyingConstraint:",
        "- startMonitoringForRegion:desiredAccuracy:",
        "- startMonitoringVisits",
        "- startTechStatusUpdates",
        "- startAppStatusUpdates",
        "- startRangingBeaconsInRegion:",
        "- startUpdatingLocationWithPrompt",
        "- startRangingToPeers:intervalSeconds:",
    ]


class LocationInvocationHandler(FridaEventHandler):

    def __init__(self, logger: AnalysisEventLogger):
        super().__init__(logger)

        self.accessStatusChecked = False
        self.accessRequested = False
        self.locationRequestedCount = 0
        self.monitoringRequestedCount = 0
        self.configured = False
        self.libsIncluded = {
            "CLLocationManager": "hooking failed",
        }

    def configure(self, script: any):
        self.configured = True

        hook_error = 0

        # auth status check
        try:
            script.exports.hook_class_method(
                'CLLocationManager', '+ authorizationStatus')
            self.libsIncluded["CLLocationManager"] = True
        except:
            hook_error += 1
            pass

        # starting in iOS 14, authorizationStatus is now an instance variable instead of a static variable
        try:
            script.exports.hook_class_method(
                'CLLocationManager', '- authorizationStatus')
            self.libsIncluded["CLLocationManager"] = True
        except:
            hook_error += 1
            pass

        if hook_error == 2:
            self.libsIncluded["CLLocationManager"] = False
        # END auth status check

        try:
            # auth request
            FridaEventHandler.hook_class_methods(script, 'CLLocationManager',
                                                 LocationInvocationHandlerMethods.auth_methods)

            # request location
            FridaEventHandler.hook_class_methods(script, 'CLLocationManager',
                                                 LocationInvocationHandlerMethods.location_request_methods)

            # start monitoring
            FridaEventHandler.hook_class_methods(script, 'CLLocationManager',
                                                 LocationInvocationHandlerMethods.location_monitoring_methods)
        except:
            logging.error(
                "hooking CLLocationManager incomplete/failed, maybe some method is no longer available")
            self.libsIncluded["CLLocationManager"] = "hooking failed, maybe some method is no longer available"

    def handle_event(self, event: FridaEvent):
        if event['name'] != FridaEventIdentifiers.InvocationEvent \
                or event['className'] != 'CLLocationManager':
            return

        if event['methodName'] in ['+ authorizationStatus', '- authorizationStatus']:
            self.evtLogger.log(AccessTypes.Location,
                               'access_status_checked', {'event': event})
            self.accessStatusChecked = True
        elif event['methodName'] in LocationInvocationHandlerMethods.auth_methods:
            self.evtLogger.log(AccessTypes.Location,
                               'access_requested', {'event': event})
            self.accessRequested = True
        elif event['methodName'] in LocationInvocationHandlerMethods.location_request_methods:
            self.evtLogger.log(AccessTypes.Location,
                               'location_requested', {'event': event})
            self.locationRequestedCount += 1
        elif event['methodName'] in LocationInvocationHandlerMethods.location_monitoring_methods:
            self.evtLogger.log(AccessTypes.Location,
                               'monitoring_requested', {'event': event})
            self.monitoringRequestedCount += 1

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        if not self.configured:
            return "NOT CONFIGURED"

        requirementsDict = super().check_requirements(self.libsIncluded, info_plist,
                                                      required_usage_descriptions=[
                                                          "NSLocationWhenInUseUsageDescription"],
                                                      optional_usage_descriptions=["NSLocationAlwaysAndWhenInUseUsageDescription"])
        privacyLabelDict = super().check_privacy_label(
            app_store_info, 'LOCATION', [])

        return {
            "privacyLabel": privacyLabelDict,
            "accessStatusChecked": self.accessStatusChecked,
            "accessRequested": self.accessRequested,
            "requirements": requirementsDict,
            "metrics": {
                "locationRequestedCount": self.locationRequestedCount,
                "monitoringRequestedCount": self.monitoringRequestedCount
            }
        }
