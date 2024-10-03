import logging
from os import EX_DATAERR
import functools

from ...constants import AccessTypes
from ...loggers import AnalysisEventLogger
from ...constants import FridaEventIdentifiers
from ...model import FridaEvent
from ..FridaEventHandler import FridaEventHandler


class PhotosInvocationHandler(FridaEventHandler):
    def __init__(self, logger: AnalysisEventLogger) -> None:
        super().__init__(logger)

        self.configured = False
        self.libsIncluded = {
            "PHPhotoLibrary": "check failed",
            "PHAsset": "check failed"
        }
        self.accessStatusChecked = False
        self.accessRequested = False
        self.requestCount = 0
        self.usage_description_key = "NSPhotoLibraryUsageDescription"

        logging.info("listening for photos access...")

    def configure(self, script):
        self.configured = True

        photo_access_methods = [
            "+ fetchAssetsForBehavioralCurationWithOptions:",
            "+ fetchAssetsWithLocalIdentifiers:options:",
            "+ fetchAssetsForReferences:photoLibrary:",
            "+ fetchAssetsMatchingMasterFingerPrint:photoLibrary:",
            "+ fetchAssetsGroupedByFaceUUIDForFaces:",
            "+ fetchAssetsMatchingAdjustedFingerPrint:photoLibrary:",
            "+ fetchAssetsWithOptions:",
            "+ fetchAssetsInBoundingBoxWithTopLeftLocation:bottomRightLocation:options:",
            "+ fetchAssetsInImportSessions:options:",
            "+ fetchAssetsWithUUIDs:options:",
            "+ fetchAssetsInAssetCollection:options:",
            "+ fetchAssetsWithoutOriginalsInAssetCollection:options:",
            "+ fetchAssetsWithMediaType:options:",
            "+ fetchAssetsWithCloudIdentifiers:options:",
            "+ fetchAssetsWithALAssetURLs:options:",
            "+ fetchAssetsWithBurstIdentifier:options:",
            "+ fetchAssetsForPerson:options:",
            "+ fetchAssetsForPersons:options:",
            "+ fetchAssetsForFaces:options:",
            "+ fetchAssetsForFaceGroups:options:",
            "+ fetchAssetsNeedingSceneProcessingWithOptions:",
            "+ fetchAssetsAllowedForSceneProcessingWithOptions:",
            "+ fetchAssetsWithObjectIDs:options:",
            "+ fetchAssetsInAssetCollections:options:",
            "+ fetchAssetsForKeywords:options:",
            "+ fetchAssetsFromCameraSinceDate:options:"
        ]

        photo_auth_methods = [
            "+ requestAuthorization:",
            "+ requestAuthorizationForAccessLevel:handler:",
            "+ authorizationStatus",
            "+ authorizationStatusForAccessLevel:",
            "+ checkAuthorizationStatusForAPIAccessLevel:",
        ]

        try:
            for method in photo_access_methods:
                script.exports.hook_class_method('PHAsset', method)

            self.libsIncluded["PHAsset"] = True
        except:
            logging.exception("hooking PHAsset incomplete")
            self.libsIncluded["PHAsset"] = False

        try:
            for method in photo_auth_methods:
                script.exports.hook_class_method('PHPhotoLibrary', method)

            self.libsIncluded["PHPhotoLibrary"] = True
        except:
            logging.error("hooking PHPhotoLibrary failed")
            self.libsIncluded["PHPhotoLibrary"] = False

    def handle_event(self, event: FridaEvent):
        if event['name'] != FridaEventIdentifiers.InvocationEvent:
            return

        # access photos
        if event['className'] == "PHAsset":
            logging.info("Photos requested")
            self.requestCount += 1
            self.evtLogger.log(AccessTypes.Photos,
                               'photos_requested', {'event': event})
            return

        if event['className'] != "PHPhotoLibrary":
            return

        # auth status check
        if 'authorizationStatus'.lower() in event['methodName'].lower():
            self.accessStatusChecked = True
            self.evtLogger.log(AccessTypes.Photos,
                               'access_status_checked', {'event': event})
            logging.info("Photos accessStatusChecked")

        # auth status request
        if 'requestAuthorization'.lower() in event['methodName'].lower():
            self.accessRequested = True
            self.evtLogger.log(AccessTypes.Photos,
                               'access_requested', {'event': event})
            logging.info("Photos access requested")

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
                "photoLibraryAccessed": self.requestCount > 0,
                "photoLibraryAccessCount": self.requestCount
            }
        }
