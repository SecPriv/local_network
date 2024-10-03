#!/usr/bin/env python3

import logging
import random
import time
from queue import LifoQueue

from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from appium.webdriver.common.appiumby import AppiumBy

logging.Formatter.converter = time.gmtime

class ExplorationStrategy():
    """Handles app state analysis and decides on steps to take next."""

    def __init__(self, session):
        """Set up with existing ExplorationSession."""
        self.session = session
        self.logger = logging.getLogger(self.__class__.__name__)

        # only initialize logger once for the class
        if not self.logger.hasHandlers:
            self.logger.setLevel(logging.DEBUG)
            logger_handler = logging.StreamHandler()
            logger_handler.setFormatter(logging.Formatter(
                '%(asctime)s: (%(levelname)s) %(name)s: %(message)s'))
            self.logger.addHandler(logger_handler)

    def start(self, steps: int = 1000):
        """Start automatic exploration.

        Keyword arguments:
        steps -- The amount of steps to take to explore the app. Defaults to 1000.
        """
        self.logger.info('Starting exploration for {} steps'.format(steps))
        for i in range(1, steps+1):
            self.session.benchmark.before_step(step=i)
            self.logger.info(f'Starting exploration step {i}')
            try:
                self.execute_next_step()
            except KeyboardInterrupt:
                self.logger.info('Received keyboard interrupt, skipping remaining UI automation steps.')
                raise
            except:
                self.logger.exception(f'Failed to execute step {i}')
            self.session.benchmark.after_step(step=i)

    def execute_next_step(self):
        raise NotImplementedError


class RandomButtonExplorationStrategy(ExplorationStrategy):
    """Explores an app by randomly tapping visible buttons."""

    def execute_next_step(self):
        """Searches for visible buttons and selects one to tap at random."""

        self.logger.info('Executing next step')
        visible_buttons = self.session.appium_wd_app.find_elements(by = AppiumBy.IOS_PREDICATE,
            value = "type == 'XCUIElementTypeButton' AND visible == 1")
        if len(visible_buttons) == 0:
            self.logger.info('No visible buttons found')
        else:
            selected_button = random.choice(visible_buttons)
            self.logger.info(
                'Pressing visible button {}'.format(selected_button))
            selected_button.click()


class NonRepeatingRandomButtonExplorationStrategy(ExplorationStrategy):
    """Explores an app by randomly tapping visible buttons at most once per run."""

    def __init__(self, session):
        super().__init__(session)
        self.tapped_buttons = []

    def execute_next_step(self):
        """Searches for visible buttons and taps one that hasn't been selected before at random."""
        visible_buttons = self.session.appium_wd_app.find_elements(by = AppiumBy.IOS_PREDICATE,
            value = "type in {'XCUIElementTypeButton', 'XCUIElementTypeToolbarButton'} AND visible == 1")
        visible_buttons_untapped = list(
            filter(lambda b: b not in self.tapped_buttons, visible_buttons))
        if len(visible_buttons) == 0:
            self.logger.info('No visible buttons found, doing nothing')
            return
        elif len(visible_buttons_untapped) == 0:
            self.logger.info(
                'No visible untapped buttons found, selecting from tapped ones')
            visible_buttons_untapped = visible_buttons

        self.logger.info('Selecting from {} visible untapped buttons'.format(
            len(visible_buttons_untapped)))
        selected_button = random.choice(visible_buttons_untapped)
        self.tapped_buttons.append(selected_button)
        self.logger.info('Pressing visible button {}'.format(selected_button))
        selected_button.click()


class iOSExplorationStrategy(ExplorationStrategy):
    """Handles iOS-specifig analysis.
    """

    class XCUIElement():
        def __init__(self, properties_dict):
            for key in properties_dict:
                if key != 'children':
                    setattr(self, key, properties_dict[key])

        def __eq__(self, other):
            comparison_values = ['type', 'rect', 'name', 'label']
            for attribute_name in comparison_values:
                if getattr(self, attribute_name, None) != getattr(other, attribute_name, None):
                    return False
            return True

        def __lt__(self, other):
            return (self.depth > other.depth) and (
                self.rect('y'), self.rect(
                    'x') < other.rect('y'), other.rect('x')
            )

        def __hash__(self):
            return hash((frozenset(self.rect),
                         self.label if self.label else "",
                         self.name if self.name else "",
                         self.value if self.value else ""
                         ))

    # https://developer.apple.com/documentation/xctest/xcuielementtype
    WIDGET_BUTTON_CLASSES = [
        'Button',
        'Cell',
        'Link',
        'Menu',  # ?
        'MenuBarItem',
        'MenuButton',
        'MenuItem',
        'TabBar',
        'ToolbarButton',
    ]
    WIDGET_INPUT_CLASSES = [
        'TextField',
        'CheckBox',
        'Picker',
        'PickerWheel',
        'RadioButton',  # RadioGroup?
        'SearchField,'
        'SecureTextField',
        'SegmentedControl',
        'Slider',
        'Stepper',
        'Switch',
        'TextField',
        'Toggle',
    ]
    WIDGET_SKIP_CLASSES = [
        'Keyboard',
        'StatusBar',
    ]
    LOGIN_GOOGLE_USER = 'pebaujb01@gmail.com'

    tapped_buttons = []

    def get_alert_accept_button(self):
        driver = self.session.appium_wd
        self.logger.debug('looking for alert')

        try:
            alert = driver.find_element(by = AppiumBy.IOS_PREDICATE,
                value = "type == 'XCUIElementTypeAlert'")
            self.logger.info(f'found alert: "{getattr(alert, "text", "no text")}"')
        except NoSuchElementException:
            self.logger.debug('no alert found')
            return None

        try:
            self.logger.info('inspecting alert buttons...')
            buttons = driver.find_elements(by = AppiumBy.XPATH,
            value = "//XCUIElementTypeAlert//XCUIElementTypeButton")

            accept_button_texts = ["ok", "okay", "accept", "allow"]
            for button in buttons:
                label = button.text
                words = label.lower().split()

                # check if first word is any of the 'accept' words
                if len(words) > 0 and words[0] in accept_button_texts:
                    self.logger.info(
                        f"found accept button with label '{label}'")
                    return button

        except NoSuchElementException:
            self.logger.debug('no alert accept button found.')
            return None

    def score_button_widgets(self, button_widgets, graph):
        selected_button = None
        for bt in button_widgets:
            bt_label = getattr(bt, 'label', '')
            bt.score = 1000
            bt.score *= bt.depth / 10
            bt.score *= int(bt.isVisible)
            bt.score *= int(bt.isEnabled)
            bt.score += 500 * \
                (1 if bt_label and 'log in' in bt_label.lower() else 0)
            bt.score -= 500 * \
                (1 if bt_label and 'dictate' in bt_label.lower() else 0)
            bt.score -= 500 * \
                (1 if bt_label and 'allow' in bt_label.lower() else 0)
            tap_count = len([t for t in self.tapped_buttons if bt.__eq__(t)])
            bt.score /= (tap_count + 1) if tap_count > 0 else 1
                        
            if not selected_button or bt.score > selected_button.score:
                selected_button = bt

        if not selected_button:
            self.logger.info('No buttons found')
            return

        return button_widgets, selected_button

    def execute_next_step(self):
        """Analyse current screen and generate appropriate inputs.

        A single step may consist of multiple on-screen actions, e.g. text input and taps.
        """
        # make sure app stays active (e.g. no navigation into system settings)
        self.session.appium_wd.execute_script(
            'mobile: activateApp', {'bundleId': self.session.app.bundle_id})

        # by default, try to accept all alerts first (e.g. permission requests)
        alert_accept_button = self.get_alert_accept_button()
        if alert_accept_button != None:
            self.logger.info('Tapping alert accept button')
            alert_accept_button.click()
            return

        # if no 'accept' button exists, further process user interface
        (graph, widgets_input, widgets_buttons) = self.parse_json_source()

        (scored_button_widgets, selected_button) = self.score_button_widgets(
            widgets_buttons, graph)
        # Determine input widget order
        # widgets_input_sorted = sorted(widgets_input)

        # Tap selected button
        if not selected_button:
            self.logger.info(
                'no button found, sleeping 1s - maybe something comes up')
            time.sleep(1)
            return

        self.tapped_buttons.append(selected_button)

        try:
            self.logger.debug('Selected {} button {} with score {}, hash {} to tap: {}'.format(
                selected_button.type, selected_button.label, selected_button.score, hash(selected_button), selected_button.__dict__))
            self.session.appium_wd.find_element(by = AppiumBy.IOS_PREDICATE,
                value = """type == 'XCUIElementType{type}'
                AND rect.x == {x} AND rect.y == {y}
                AND rect.width == {width} AND rect.height == {height}"""
                                                                 .format(type=selected_button.type,
                                                                         x=selected_button.rect['x'],
                                                                         y=selected_button.rect['y'],
                                                                         width=selected_button.rect['width'],
                                                                         height=selected_button.rect['height']
                                                                         )).click()

            try:
                bt_label = getattr(selected_button, 'label', '')
                if bt_label and ' with google' in bt_label.lower():
                    WebDriverWait(self.session.appium_wd, 10, 1).until(
                        lambda x: x.find_element_by(by = AppiumBy.IOS_PREDICATE,
                        value = "type == 'XCUIElementTypeAlert'"))
                    self.session.appium_wd.execute_script(
                        'mobile: alert', {'action': 'accept'})
                    self.login_with_google()
            except AttributeError as e:
                self.logger.error(
                    'AttributeError occured when looking for Google button: {}'.format(str(e)))
        except NoSuchElementException as e:
            self.logger.error(
                'Could not find selected button to tap: {}'.format(str(e)))

    def parse_json_source(self):
        """Fetch JSON representation of current app state and create view hierarchy graph,
        input and button widget lists.
        """
        json_source = self.session.appium_wd.execute_script(
            'mobile:source', {'format': 'json'})

        graph = {}
        widgets_input = []
        widgets_buttons = []
        queue = LifoQueue()

        json_source['depth'] = 0
        queue.put((json_source, None))

        while not queue.empty():
            (element, parent) = queue.get()
            converted_element = self.XCUIElement(element)
            if converted_element.type in self.WIDGET_SKIP_CLASSES:
                self.logger.info('Ignoring element with type: {}'.format(
                    converted_element.type))
                continue
            graph[converted_element] = []
            if parent:
                graph[converted_element] = [parent]
                graph[parent].append(converted_element)
            if converted_element.type in self.WIDGET_BUTTON_CLASSES:
                widgets_buttons.append(converted_element)
            elif converted_element.type in self.WIDGET_INPUT_CLASSES:
                widgets_input.append(converted_element)
            if 'children' in element:
                for child in element['children']:
                    child['depth'] = converted_element.depth + 1
                    queue.put((child, converted_element))

        return (graph, widgets_input, widgets_buttons)

    def login_with_google(self):
        """ Handles SSO login flow using Google accounts.
        """
        self.logger.info('Logging in with Google Account')
        if not self.LOGIN_GOOGLE_USER:
            self.logger.error('Google user name not set')
            return
        try:
            account_selection_link = WebDriverWait(self.session.appium_wd, 10, 1).until(lambda x: x.find_element_by_ios_predicate(
                "type == 'XCUIElementTypeLink' AND name LIKE[c] '{}*'".format(self.LOGIN_GOOGLE_USER)))
            self.logger.info('Successfully waited for account selection link: {}'.format(
                account_selection_link))
        except TimeoutException:
            self.logger.info('Did not find account selection link in time')
            return
        account_selection_link.click()
        WebDriverWait(self.session.appium_wd, 10).until_not(lambda x: x.find_element(by = AppiumBy.IOS_PREDICATE,
            value = "type == 'XCUIElementTypeLink' AND name LIKE [c] '{}*'".format(self.LOGIN_GOOGLE_USER)))
        self.logger.info('Google login flow ended')


class iOSAcceptOnlySystemDialogs(iOSExplorationStrategy):
    """Only Accept System Dialogs."""

    def score_button_widgets(self, button_widgets, graph):
        return (None, None)


class iOSDFSExplorationStrategy(iOSExplorationStrategy):
    """Depth-first search exploring views in detail before switching to different ones."""

    def score_button_widgets(self, button_widgets, graph):
        selected_button = None
        for bt in button_widgets:
            if bt.isVisible == '0' or bt.isEnabled == '0':
                bt.score = 0
            elif bt.label and "google" in bt.label:
                bt.score = 100
            else:
                bt.score = bt.depth
                tap_count = len(
                    [t for t in self.tapped_buttons if bt.__eq__(t)])
                if tap_count:
                    bt.score /= tap_count * 2
            if not selected_button or bt.score > selected_button.score:
                selected_button = bt

        if not selected_button:
            self.logger.info('No buttons found')
            return (None, None)

        return button_widgets, selected_button


class iOSBFSExplorationStrategy(iOSExplorationStrategy):
    """Breadth-first search focusing on visiting different views."""

    def score_button_widgets(self, button_widgets, graph):
        selected_button = None
        for bt in button_widgets:
            if bt.isVisible == '0' or bt.isEnabled == '0':
                bt.score = 0
            else:
                bt.score = 100 * (1/bt.depth)
                tap_count = len(
                    [t for t in self.tapped_buttons if bt.__eq__(t)])
                if tap_count:
                    bt.score /= tap_count * 2
            if not selected_button or bt.score > selected_button.score:
                selected_button = bt

        if not selected_button:
            self.logger.info('No buttons found')
            return (None, None)

        return button_widgets, selected_button


class iOSRandomButtonExplorationStrategy(iOSExplorationStrategy):
    """Selecting visible, enabled buttons at random.
    """

    def score_button_widgets(self, button_widgets, graph):
        selected_button = None
        for bt in button_widgets:
            if bt.isVisible == '1' and bt.isEnabled == '1':
                bt.score = random.randint(0, 100)
            else:
                bt.score = 0
            if not selected_button or bt.score > selected_button.score:
                selected_button = bt

        if not selected_button:
            self.logger.info('No buttons found')
            return (None, None)

        return button_widgets, selected_button
