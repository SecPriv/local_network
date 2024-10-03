from __future__ import annotations

from contextlib import suppress
import logging
from typing import Optional

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait

from .app import AndroidApp
from .device import AndroidDevice
from .ui_automator.constants import (
    ANDROID_PLAY_STORE_MAIN_ACTIVITY,
    INSTALL_DURATION_IN_SECONDS,
    WAIT_DURATION_IN_SECONDS,
)
from ..helper.constants import LOGGER_BASE_NAME

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".android.play-store-installer")


class PlayStoreInstaller:
    """
    Provides an interface for easy installation of an app from Google Play Store.
    """

    appium_wd: webdriver.Remote
    installed_app: AndroidApp
    device: AndroidDevice

    def __init__(self, device: AndroidDevice, appium_address: str):
        """
            Starts Appium session for installation of an app using Google Play.

            Args:
                device: Object holding all data of the test device
                appium_address: Fully qualified address of the appium server
        """
        desired_caps = {
            "platformName": "Android",
            "automationName": "UiAutomator2",
            "platformVersion": device.platform_version,
            "deviceName": device.name,
            "udid": device.udid,
            "newCommandTimeout": 600,
            "avd": device.avd_name,
        }
        self.device = device

        logger.info("Starting Appium session for Google Play Store")
        self.appium_wd = webdriver.Remote(appium_address, desired_caps)

    def install_app_from_play_store(self, app_package: str) -> Optional[AndroidApp]:
        """
        Installs an app from the Play Store and returns the parsed app package,
        if installation fails, None is returned instead.

        Args:
            app_package: Package name of the app to be installed

        Returns:
            Object holding all available data about the app, if installation succeeded, else None
        """
        logger.info(f'Trying to install "{app_package}" from Google Play Store')

        if self.appium_wd.is_app_installed(app_package):
            logger.debug(f"App is already installed, uninstalling it first")
            self.appium_wd.remove_app(app_package)

        # Navigate to the specific play store page directly
        self.appium_wd.execute_script(
            "mobile: shell",
            {
                "command": "am",
                "args": [
                    "start -a android.intent.action.VIEW -d "
                    + f'"https://play.google.com/store/apps/details?id={app_package}"'
                ],
            },
        )

        # Don't check for display name

        logger.debug("Clicking install.")
        # tap on the Install button
        WebDriverWait(self.appium_wd, WAIT_DURATION_IN_SECONDS).until(
            expected_conditions.visibility_of_element_located(
                (
                    AppiumBy.ANDROID_UIAUTOMATOR,
                    f'new UiSelector().className("android.widget.Button").text("Install")',
                )
            ),
            message=f'timed out while waiting for "Install" button (Timeout = {WAIT_DURATION_IN_SECONDS} seconds)',
        ).click()

        try:
            # wait until disabled "Open"-button shows up for WAIT_DURATION_IN_SECONDS
            WebDriverWait(self.appium_wd, WAIT_DURATION_IN_SECONDS).until(
                expected_conditions.presence_of_element_located(
                    (
                        AppiumBy.ANDROID_UIAUTOMATOR,
                        'new UiSelector().className("android.widget.Button").text("Open")'
                        ".clickable(false).enabled(false)",
                    )
                ),
                message=f'timed out while waiting for disabled "Open" button '
                        f"(Timeout = {WAIT_DURATION_IN_SECONDS} seconds)",
            )
        except TimeoutException:
            logger.debug("Detected additional dialog, trying to handle it.")
            with suppress(NoSuchElementException):
                el = self.appium_wd.find_element(AppiumBy.ANDROID_UIAUTOMATOR,
                                                 'new UiSelector().className("android.widget.Button").textStartsWith('
                                                 '"Continue") '
                                                 )
                el.click()
            with suppress(NoSuchElementException):
                el = self.appium_wd.find_element(AppiumBy.ANDROID_UIAUTOMATOR,
                                                 'new UiSelector().className("android.widget.Button").textStartsWith('
                                                 '"Skip") '
                                                 )
                el.click()
            logger.debug("Dialog should be handled successfully.")
            WebDriverWait(self.appium_wd, WAIT_DURATION_IN_SECONDS).until(
                expected_conditions.presence_of_element_located(
                    (
                        AppiumBy.ANDROID_UIAUTOMATOR,
                        'new UiSelector().className("android.widget.Button").text("Open")'
                        ".clickable(false).enabled(false)",
                    )
                ),
                message=f'timed out while waiting for disabled "Open" button '
                        f"(Timeout = {WAIT_DURATION_IN_SECONDS} seconds)",
            )

        # wait until download starts for INSTALL_DURATION_IN_SECONDS
        logger.debug("Waiting for download to start.")
        WebDriverWait(self.appium_wd, WAIT_DURATION_IN_SECONDS).until_not(
            expected_conditions.presence_of_element_located(
                (
                    AppiumBy.ANDROID_UIAUTOMATOR,
                    'new UiSelector().className("android.widget.TextView").text("Waiting for download")',
                )
            ),
            message=f'timed out while waiting for "Waiting for download" text '
                    f"(Timeout = {WAIT_DURATION_IN_SECONDS} seconds)",
        )

        # wait until "Open"-button shows up for INSTALL_DURATION_IN_SECONDS
        logger.debug("Waiting for installation to finish.")
        WebDriverWait(self.appium_wd, INSTALL_DURATION_IN_SECONDS).until(
            expected_conditions.presence_of_element_located(
                (
                    AppiumBy.ANDROID_UIAUTOMATOR,
                    'new UiSelector().className("android.widget.Button").text("Open").clickable(true).enabled(true)',
                )
            ),
            message=f'timed out while waiting for enabled "Open" button '
                    f"(Timeout = {INSTALL_DURATION_IN_SECONDS} seconds)",
        )

        if self.appium_wd.is_app_installed(app_package):
            logger.info(f"{app_package} has been successfully installed.")

            installed_apk_path = self.device.extract_apk(pkg_name=app_package)
            if installed_apk_path:
                self.installed_app = AndroidApp(installed_apk_path)

            if self.installed_app:
                self.installed_app.install_source = "GOOGLE_PLAY"

            self.appium_wd.terminate_app(ANDROID_PLAY_STORE_MAIN_ACTIVITY.package.name)

            self.appium_wd.quit()

            # Returns installed_app if everything went fine, else returns None
            return self.installed_app
        else:
            logger.error(
                f'Could not find app with package name "{app_package}"'
            )

            self.appium_wd.quit()

            return None
