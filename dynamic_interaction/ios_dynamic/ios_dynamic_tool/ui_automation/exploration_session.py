#!/usr/bin/env python3

from dataclasses import dataclass
import logging

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from urllib3.exceptions import MaxRetryError

from . import exploration_benchmarks as benchmarks
from . import exploration_strategies as explorers


@dataclass
class iOSDevice():
    """Encapsulates information about a iOS-based test device."""
    udid: str
    name: str = "iOS Device"


@dataclass
class iOSApp():
    """Encapsulates information about a iOS-app."""
    bundle_id: str


class ExplorationSession():
    """Handles Appium-based test sessions."""

    def __init__(self, command_executor: str, xcode_org_id: str, device: iOSDevice, app: iOSApp, device_ip: str = None):
        """Prepare a test session.

        Keyword arguments:
        command_executor -- URL of the WDA server to use as a mediator.
        xcode_org_id -- see https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/
        device -- information about the device on which tests are executed.
        app -- the app to run tests on.
        """
        self.command_executor = command_executor
        self.xcode_org_id = xcode_org_id
        self.device = device
        self.app = app
        self.appium_wd = None
        self.appium_wd_app = None
        self.explorer = None
        self.benchmark = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        logger_handler = logging.StreamHandler()
        logger_handler.setFormatter(logging.Formatter(
            '%(asctime)s: (%(levelname)s) %(name)s: %(message)s'))
        self.logger.addHandler(logger_handler)
        self.device_ip = device_ip

    def __del__(self):
        if self.appium_wd:
            self.logger.info('Quitting Appium session')
            self.appium_wd.quit()

    def start(self):
        """Start an Appium-session using the device and app provided during initialization."""
        if not self.appium_wd:
            desired_caps = {
                'platformName': 'iOS',
                'automationName': 'XCUITest',
                'deviceName': self.device.name,
                'udid': self.device.udid,
                # 'bundleId': self.app.bundle_id,
                # if `app` is present, the app is started. if not, appium attaches to the frontmost app instead
                # 'app': self.app.bundle_id,
                'useJSONSource': True,
                'newCommandTimeout': 600,
                #"xcodeOrgId": self.xcode_org_id, # "9B2SDNGX24",
                #"xcodeSigningId": "Apple Development",
                "usePrebuiltWDA": True
                #"xcodeSigningId": "iPhone Developer",
                # "autoAcceptAlerts": True # does not work reliably since iOS 13. implemented it manually instead
            }
            if self.device_ip:
                desired_caps["wdaBaseUrl"] = f"http://{self.device_ip}"
            self.logger.info('Starting session')

            try:
                self.appium_wd = webdriver.Remote(
                    self.command_executor, desired_caps)
            except MaxRetryError:
                self.logger.error('Could not connect to Appium (WDA command executor)')
                raise

            self.appium_wd_app = self.appium_wd.find_element(by = AppiumBy.CLASS_NAME, value = 'XCUIElementTypeApplication')

    def stop(self):
        """Quits a running Appium session."""
        if self.appium_wd:
            self.logger.info('Quitting Appium session')
            self.appium_wd.quit()
            self.appium_wd = None
            self.appium_wd_app = None

    def explore(self, explorer: explorers.ExplorationStrategy = explorers.ExplorationStrategy,
                benchmark: benchmarks.ExplorationBenchmark = benchmarks.ExplorationBenchmark,
                steps: int = 1000):
        """Explore the app automatically.

        Keyword arguments:
        explorer -- ExplorationStrategy handling actual app analysis and control.
        benchmark -- ExplorationBenchmark analysing and measuring explorer behaviour.
        steps -- number of steps for which app should be explored. Defaults to 1000.
        """
        if not self.appium_wd:
            self.logger.info('No Appium session found, starting new one.')
            self.start()
        self.explorer = explorer(self)
        self.benchmark = benchmark(self)
        self.explorer.start(steps=steps)
        self.explorer = None
        self.benchmark = None
