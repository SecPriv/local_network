import logging
import re
from urllib.parse import urlparse

from ...loggers import AnalysisEventLogger
from ...constants import FridaEventIdentifiers
from ...constants import AccessTypes
from ...model import FridaEvent
from ..FridaEventHandler import FridaEventHandler


class NetworkRequestHandler(FridaEventHandler):

    def __init__(self, logger: AnalysisEventLogger, assets_folder: str) -> None:
        """
        In order to check whether called urls are known tracking urls, this class loads a list of such known
        urls from a dnsmasq.blacklist.txt file present in the provided assets_folder

        It can be obtained from github:
        https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnsmasq/dnsmasq.blacklist.txt
        """
        super().__init__(logger)

        self.configured = False
        self.domains_with_count = {}
        self.tracking_domains_with_count = {}
        self._assets_folder = ''
        self._tracking_urls = set()

        self._assets_folder = assets_folder

    def configure(self, script):
        self.configured = True

        # load file with known tracking urls
        self._load_tracking_urls()

        script.exports.hook_url_direct()

        logging.info("listening for URL calls...")

    def handle_event(self, event: FridaEvent):
        if event['name'] == FridaEventIdentifiers.NetworkEvent:
            self.handle_network_event(event)
            return

    def handle_network_event(self, event: FridaEvent):
        url = urlparse(event.url).netloc

        is_tracking_url = self._tracking_urls.__contains__(url)
        if is_tracking_url:
            logging.info(f'tracking domain accessed - {url}')
            self.count_domain(self.tracking_domains_with_count, url)
        else:
            logging.info(f'non-tracking domain accessed - {url}')
            self.count_domain(self.domains_with_count, url)

        self.evtLogger.log(AccessTypes.Network, 'network_request', {
                           'url': event.url,
                           'method': event.method,
                           'is_tracking_url': is_tracking_url})

    def count_domain(self, count_dict: dict, url: str):
        if url in count_dict.keys():
            count_dict[url] += 1
        else:
            count_dict[url] = 1

    def report(self, info_plist: dict, app_store_info: dict) -> dict:
        if not self.configured:
            return "NOT CONFIGURED"

        return {
            "trackingDomainsDetected": len(self.tracking_domains_with_count) > 0,
            "trackingDomains": self.tracking_domains_with_count,
            "domains": self.domains_with_count,
        }

    def _load_tracking_urls(self):
        filename = self._assets_folder + 'dnsmasq.blacklist.txt'
        logging.info(f'loading known tracking urls from {filename}')

        try:
            with open(filename) as f:
                for line in f:
                    if line.startswith('#'):
                        continue

                    # line format: address=/0-24bpautomentes.hu/#
                    matches = re.findall('\/(.*)\/', line)
                    if len(matches) == 1:
                        url = matches[0]
                        self._tracking_urls.add(url)
                    else:
                        logging.error(
                            f'error, found less or more than one address in line: {line} - skipping')

                logging.info(
                    f'{len(self._tracking_urls)} known tracking urls loaded')
        except Exception as e:
            logging.exception(f'failed to load known tracking urls')
