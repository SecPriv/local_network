import functools
import logging

from ...constants import AccessTypes
from ...model import InvocationEvent
from ...loggers import AnalysisEventLogger
from ...constants import FridaEventIdentifiers
from ...model import FridaEvent
from ..FridaEventHandler import FridaEventHandler


class ContactsInvocationHandlerMethods:
    " could be extended to also check which CNContact fields are accessed "

    contact_enumeration_methods = [
        "- enumerateContactsAndMatchInfoWithFetchRequest:error:usingBlock:",
        "- enumerateContactsWithFetchRequest:error:usingBlock:",
        "- enumerateNonUnifiedContactsWithFetchRequest:error:usingBlock:",
        "- enumeratorForContactFetchRequest:error:"
    ]

    personal_contact_access_methods = [
        "- unifiedMeContactMatchingEmailAddresses:keysToFetch:error:",
        "- unifiedMeContactWithKeysToFetch:error:",
        "- unifiedMeContactMatchingEmailAddress:keysToFetch:error:"
    ]

    contact_search_methods = [
        "- unifiedContactsMatchingPredicate:keysToFetch:error:",
        "- unifiedContactWithIdentifier:keysToFetch:error:",
        "- unifiedContactCountWithError:"
    ]


class ContactsInvocationHandler(FridaEventHandler):

    def __init__(self, logger: AnalysisEventLogger) -> None:
        super().__init__(logger)

        self.configured = False
        self.contacts_enumerated_count = 0
        self.personal_contact_requested_count = 0
        self.contact_search_count = 0
        self.libsIncluded = {
            "CNContactStore": "check failed"
        }
        self.accessStatusChecked = False
        self.accessRequested = False
        self.requestCount = 0
        self.usage_description_key = "NSContactsUsageDescription"

        logging.info("listening for contacts access...")

    def configure(self, script):
        self.configured = True

        try:
            # access status check
            script.exports.hook_class_method(
                'CNContactStore', '+ authorizationStatusForEntityType:')

            # access request
            script.exports.hook_class_method(
                'CNContactStore', '- requestAccessForEntityType:')
            script.exports.hook_class_method(
                'CNContactStore', '- requestAccessForEntityType:completionHandler:')
            script.exports.hook_class_method(
                'CNContactStore', '- requestAuthorization:entityType:completionHandler:')  # optional

            # contacts fetch / enumerate
            for method in ContactsInvocationHandlerMethods.contact_enumeration_methods:
                script.exports.hook_class_method('CNContactStore', method)

            for method in ContactsInvocationHandlerMethods.contact_search_methods:
                script.exports.hook_class_method('CNContactStore', method)

            for method in ContactsInvocationHandlerMethods.personal_contact_access_methods:
                script.exports.hook_class_method('CNContactStore', method)

            self.libsIncluded["CNContactStore"] = True
        except:
            logging.exception("hooking CNContactStore failed")
            self.libsIncluded["CNContactStore"] = False

    def handle_event(self, event: FridaEvent):
        if event['name'] != FridaEventIdentifiers.InvocationEvent:
            return

        if event['className'] == "CNContactStore":
            self.handle_CNContactStore_call(event)

    def handle_CNContactStore_call(self, event: InvocationEvent):
        if 'authorizationStatus'.lower() in event['methodName'].lower():
            logging.info('Contacts accessStatusChecked')
            self.accessStatusChecked = True
            self.evtLogger.log(AccessTypes.Contacts,
                               'access_status_checked', {'event': event})
            return

        if 'requestAccess'.lower() in event['methodName'].lower():
            logging.info('Contacts accessRequested')
            self.accessRequested = True
            self.evtLogger.log(AccessTypes.Contacts,
                               'access_requested', {'event': event})
            return

        if event['methodName'] in ContactsInvocationHandlerMethods.contact_enumeration_methods:
            logging.info('Contacts enumerated')
            self.contacts_enumerated_count += 1
            self.evtLogger.log(AccessTypes.Contacts,
                               'contacts_enumerated', {'event': event})
            return

        if event['methodName'] in ContactsInvocationHandlerMethods.contact_search_methods:
            logging.info('Contacts searched')
            self.contact_search_count += 1
            self.evtLogger.log(AccessTypes.Contacts,
                               'contacts_searched', {'event': event})
            return

        if event['methodName'] in ContactsInvocationHandlerMethods.personal_contact_access_methods:
            logging.info('Contacts peronal contact requested')
            self.personal_contact_requested_count += 1
            self.evtLogger.log(AccessTypes.Contacts,
                               'personal_contact_accessed', {'event': event})
            return

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        if not self.configured:
            return "NOT CONFIGURED"

        requirementsDict = super().check_requirements(
            self.libsIncluded, info_plist, [self.usage_description_key])
        privacyLabelDict = super().check_privacy_label(
            app_store_info, 'CONTACTS', [])  # category "CONTATCT_INFO" would probably also be possible

        return {
            "privacyLabel": privacyLabelDict,
            "accessStatusChecked": self.accessStatusChecked,
            "accessRequested": self.accessRequested,
            "requirements": requirementsDict,
            "metrics": {
                "contactEnumeratedCount": self.contacts_enumerated_count,
                "contactSearchCount": self.contact_search_count,
                "personalContactRequestedCount": self.personal_contact_requested_count
            }
        }
