import functools
from abc import ABC, abstractmethod
import logging

from ..loggers import AnalysisEventLogger
from ..model import FridaEvent

def search_for_privacy_label(app_store_info: dict, category: str, data_types: list[str]) -> list[dict]:
    """ If data_types is empty, search matches any data_type in specified category """
    # api privacy details structure:
    #
    # privacyDetails: {
    #   privacyTypes: [
    #      PrivacyType
    #   ]
    # }
    #
    # PrivacyType {
    #   privacyType: str
    #   identifier: str
    #   description:
    #   dataCategories: [DataCategory]
    #   purposes: [Purpose]
    # }
    #
    # Purpose {
    #   purpose: str
    #   identifier: str
    #   dataCategories: [DataCategory]
    # }
    #
    # DataCategory {
    #   dataCategory: str
    #   identifier: str
    #   dataTypes: [str]
    # }
    #
    if app_store_info is None or app_store_info == {}:
        return []

    privacy_types = app_store_info.get("data", None)
    if len(privacy_types) >= 1:
        privacy_types = privacy_types.get("attributes", {}).get("privacyDetails", {}).get("privacyTypes", {})
    applicable_privacy_types = []

    for privacy_type in privacy_types:
        included_in_categories = False
        included_in_purposes = []

        for data_category in privacy_type.get('dataCategories'):
            if data_category.get('identifier') == category:
                for data_type in data_category.get('dataTypes'):
                    if len(data_types) == 0 or data_type in data_types:
                        included_in_categories = True

        for purpose in privacy_type.get('purposes', []):
            for data_category in purpose.get('dataCategories', []):
                if data_category.get('identifier', None) == category:
                    for data_type in data_category.get('dataTypes', []):
                        if len(data_types) == 0 or data_type in data_types:
                            included_in_purposes.append(
                                purpose.get('identifier', None))

        if included_in_categories or len(included_in_purposes) > 0:
            applicable_privacy_types.append({
                "type": privacy_type.get('identifier', None),
                "purposes": included_in_purposes
            })

    return applicable_privacy_types

class FridaEventHandler(ABC):
    def __init__(self, logger: AnalysisEventLogger):
        self.evtLogger = logger

    @abstractmethod
    def handle_event(self, event: FridaEvent):
        pass

    @abstractmethod
    def configure(self, script: any):
        pass

    @abstractmethod
    def report(info_plist: dict) -> dict:
        pass

    def check_requirements(self, libs_included: dict, info_plist: dict, required_usage_descriptions: list[str], optional_usage_descriptions: list[str] = []) -> dict:
        """
        In most cases, apps require a usage description to request a certain permission.
        Additionally, the app binary needs to contain the required libraries to access respective resource.
        This method checks if all libs are included and the usage description key is present. It returns a dict with the format specified below.
        Ignores usage descriptions that are limited to the macOS platform (see get_usage_description method)

        libs_included must be a dict with the following form: key = name of the library, value = True iff lib is included, some other value otherwise
        info_plist needs to be a parsed dict of the iOS info.plist file
        required_usage_descriptions is a list of required usage description so that the app is allowed to access
        optional_usage_descriptions is a list of usage description that may include additional user info but are not strictly required for the base functionality

        Returns dict with the following fields:
        - allRequirementsMet: bool
        - usageDescriptions: [{
            usageDescriptionKey: str,
            usageDescriptionValue: str,
            usageDescriptionPresent: bool
        }, ...]
        - libsIncluded: dict (the dict that was passed to this method)
        """

        usage_descriptions = []
        for required in required_usage_descriptions:
            usage_description = self.get_usage_description(
                info_plist, required)
            usage_descriptions.append({
                "usageDescriptionKey": required,
                "usageDescriptionPresent": usage_description != None,
                "usageDescriptionValue": usage_description,
                "required": True
            })

        for optional in optional_usage_descriptions:
            usage_description = self.get_usage_description(
                info_plist, optional)
            usage_descriptions.append({
                "usageDescriptionKey": optional,
                "usageDescriptionPresent": usage_description != None,
                "usageDescriptionValue": usage_description,
                "required": False
            })

        all_libs_included = functools.reduce(
            lambda libIncluded, val: (libIncluded == True) and (val == True), libs_included.values())
        all_required_usage_descriptions_present = functools.reduce(
            lambda val, usage_description_dict: (usage_description_dict['required'] == False or usage_description_dict['usageDescriptionPresent']) and val, usage_descriptions, True)
        all_requirements_met = all_libs_included == True and all_required_usage_descriptions_present == True

        return {
            "allRequirementsMet": all_requirements_met,
            "usageDescriptions": usage_descriptions,
            "libsIncluded": libs_included
        }

    def get_usage_description(self, info_plist: dict,
                              usage_description_title: str) -> str:
        """
        Cave: Usage descriptions can have a suffix for a specific platform or device type.
        The format is [key name]-[platform]~[device]
        e.g. "NSLocationWhenInUseUsageDescription-iphoneos" or "NSLocationWhenInUseUsageDescription-macos"
        -> we will ignore all usage descriptions for macOS

        see: https://developer.apple.com/documentation/bundleresources/information_property_list/managing_your_app_s_information_property_list

        """
        usage_description = None

        info_plist_keys = info_plist.keys()
        for key in info_plist_keys:
            if usage_description_title in key \
                    and not "macos" in key:
                usage_description = info_plist[key]

        return usage_description

    def check_privacy_label(self, app_store_info: dict, category: str, data_types: list[str]):
        applicable_privacy_types = []
        hasPrivacyLabel = False
        try:
            applicable_privacy_types = search_for_privacy_label(
                app_store_info, category, data_types)
            hasPrivacyLabel = len(applicable_privacy_types) > 0
        except Exception as e:
            logging.exception("Search for privacy labels failed: ")
            hasPrivacyLabel = "check failed"

        return {
            "hasPrivacyLabel": hasPrivacyLabel,
            "search_terms": [{
                "category": category,
                "data_types": data_types
            }],
            "declared_in_types": applicable_privacy_types
        }

    def hook_class_methods(script, className: str, methodNames: list[str]):
        """ Hooks all methods for a given class
        Call may throw if class+method combination was not found
        """

        for method in methodNames:
            script.exports.hook_class_method(className, method)


class FridaEventHandlerQueue:
    def __init__(self) -> None:
        self.event_handlers: list[FridaEventHandler] = []

    def handle_event(self, event: FridaEvent):
        # print('FridaEventHandlerQueue: handling event: %s' % event["name"])

        for handler in self.event_handlers:
            try:
                handler.handle_event(event)
            except Exception as ex:
                logging.exception(
                    'EventHandler failed to handle event, skipping..')

    def add(self, eventHandler: FridaEventHandler):
        self.event_handlers.append(eventHandler)

    def clear(self):
        self.event_handlers.clear()
