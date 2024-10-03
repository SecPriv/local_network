from ...constants import FridaEventIdentifiers
from ..FridaEventHandler import FridaEventHandlerQueue, FridaEventHandler
import logging


class SimpleInvocationCounter(FridaEventHandler):
    def __init__(self) -> None:
        # dict: invocations[class_name][method_name] = count
        self.invocations = {}

    def handle_event(self, event: FridaEventHandlerQueue):
        if event['name'] != FridaEventIdentifiers.InvocationEvent:
            return

        class_name = event['className']
        method_name = event['methodName']

        if not self.invocations.__contains__(class_name):
            self.invocations[class_name] = {}

        currentCount = 0
        if self.invocations[class_name].__contains__(method_name):
            currentCount = self.invocations[class_name][method_name]

        logging.debug(("invocation: %s %s" % (class_name, method_name)))

        currentCount += 1

        self.invocations[class_name][method_name] = currentCount

    def configure(self, script: any):
        # no hooking necessary, accepts any InvocationEvent

        pass

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        invocation_summary = {}

        for class_name in self.invocations.keys():
            methods_with_counter = self.invocations[class_name]

            invocations_sorted_desc = sorted(methods_with_counter.items(),
                                             key=(lambda item: item[1]), reverse=True)

            invocation_summary[class_name] = invocations_sorted_desc

            logging.debug(('Invocations for %s:' % class_name))
            for (method, count) in invocations_sorted_desc:
                logging.debug((method, count))

        return invocation_summary
