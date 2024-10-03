from __future__ import annotations

from contextlib import suppress
import logging
import re
from time import sleep
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ElementTree

from selenium.common.exceptions import InvalidArgumentException, InvalidElementStateException
from selenium.webdriver import ActionChains

from ..app import AndroidActivity
from .constants import ANDROID_ENTER_KEY_CODE, WIDGET_INPUT_CLASSES
from ...helper.constants import LOGGER_BASE_NAME
from ...helper.helper_functions import get_random_email, get_random_string
from ...helper.seeded_random import seeded_random

if TYPE_CHECKING:
    from .app_model import AndroidAppModel
    from appium import webdriver
    from typing import List, Optional, Tuple, Any, Set, Union

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".android.ui_automator.gui_wrapper")


def click_by_coordinates(driver: webdriver.Remote, x: int, y: int) -> bool:
    """Clicks on the screen at the specified coordinates. Does no sanity checks.

    Args:
        driver: webdriver connection to the device.
        x: x-coordinate
        y: y-coordinate

    Returns:
        Click successful
    """
    try:
        logger.info(f"Clicking on the screen at x={x} and y={y}")
        driver.tap([(x, y)])
        before_sleep = driver.current_activity
        sleep(0.3)
        after_sleep = driver.current_activity
        if after_sleep != before_sleep:
            logger.debug(
                f'############## "{after_sleep}" != "{before_sleep}" -> sleeping after clicking is necessary '
                f'############## '
            )
        return True
    except InvalidArgumentException as err:
        logger.debug(
            f'An exception occurred while trying to tap on the screen (x={x},y={y}): {str(err)}'
        )
    except InvalidElementStateException as err:
        logger.debug(
            f'An exception occurred while trying to tap on the screen (x={x},y={y}): {str(err)}'
        )
    except RuntimeError:
        logger.debug(
            f'An exception occurred while trying to tap on the screen (x={x},y={y})', exc_info=True
        )
    try:
        logger.debug(
            "Trying to recover from exception by trying to tap using `adb shell input` command"
        )
        driver.execute_script(
            "mobile: shell",
            {"command": "input", "args": ["touchscreen", "tap", str(x), str(y)]},
        )
        sleep(0.3)
        return True
    except RuntimeError:
        logger.debug(
            f'An exception occurred while trying to recover from previous error '
            f"(tap on the screen x={x},y={y})", exc_info=True
        )
    return False


class AndroidWidget:
    """Base class for Android widgets specifying all methods a subclass has to implement."""

    activity: AndroidActivity

    def is_clickable(self) -> bool:
        raise NotImplementedError

    def is_checkable(self) -> bool:
        raise NotImplementedError

    def is_displayed(self) -> bool:
        raise NotImplementedError

    def is_enabled(self) -> bool:
        raise NotImplementedError

    def get_description(
        self, recursive: bool = True, comparison: bool = False
    ) -> str:
        """Returns description of Widget.

        Args:
            recursive: If True, it attempts to recursively obtain a description for the widget from its children,
                          in case none is available for the widget itself. Else the widgets description is returned.
                          Defaults to True.
            comparison: If True, it attempts to return a description that is stable over multiple iterations. This is
                       only relevant for text input fields, where the original description can be of more value
                       than the text currently put in. Else the widgets description is returned.
                       Takes precedence over recursive. Defaults to False.

        Returns:
            Description of widget.
        """
        raise NotImplementedError

    def get_class_string(self) -> str:
        """Returns class name of widget.

        Returns:
            Class name
        """
        raise NotImplementedError

    def get_package_and_activity(self) -> AndroidActivity:
        """Returns activity and package of widget.

        Returns:
            Object containing both package and activity name.
        """
        return self.activity

    def get_boundaries_on_screen(
        self,
    ) -> Optional[Tuple[Tuple[int, int], Tuple[int, int]]]:
        """Extracts boundaries of widget from data.

        Returns:
            If known, top left and bottom right coordinates in the form ((x1, y1), (x2, y2)), else None.
        """
        raise NotImplementedError

    def click(self) -> bool:
        """Clicks on the widget.

        Returns:
            Click successful
        """
        raise NotImplementedError

    def random_input(self, hit_enter: bool = True) -> Optional[str]:
        """Inputs a random string into the widget.

        Args:
            hit_enter: If True, hits enter after input. Defaults to True.

        Returns:
            If input action is successful, the string used as input value is returned, else None.
        """
        random_str = get_random_string()
        return self.text_input(random_str, hit_enter=hit_enter)

    def text_input(
        self, input_str: str, hit_enter: bool = False
    ) -> Optional[str]:
        """Inputs a given string into the widget.

        Args:
            input_str: String used as input.
            hit_enter: If True, hits enter after input. Defaults to True.

        Returns:
            If input action is successful, the string used as input value is returned, else None.
        """
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        # Subtypes should only be considered equal, if they have the same type
        if isinstance(other, type(self)):
            return (
                self.get_package_and_activity() == other.get_package_and_activity()
                and self.get_description(recursive=False, comparison=True)
                == other.get_description(recursive=False, comparison=True)
                and self.is_clickable() == other.is_clickable()
                and self.is_checkable() == other.is_checkable()
                and self.is_displayed() == other.is_displayed()
                and self.is_enabled() == other.is_enabled()
                and self.get_boundaries_on_screen() == other.get_boundaries_on_screen()
            )
        return False

    def __hash__(self) -> int:
        # CAVEAT: due to hashes of strings being salted, these hashes are only valid for an element in a single run,
        # in the next run, the element will have a different hash!
        return hash(
            (
                self.get_package_and_activity(),
                self.get_description(recursive=False, comparison=True),
                self.get_class_string(),
                self.is_clickable(),
                self.is_checkable(),
                self.is_displayed(),
                self.is_enabled(),
                self.get_boundaries_on_screen(),
            )
        )

    def __str__(self) -> str:
        return f"AndroidWidget(class={self.get_class_string()}, desc={self.get_description()})"


class AndroidWidgetFromXML(AndroidWidget):
    """Class for Android widgets created from XML."""

    _xml_element: ElementTree.Element
    _original_text: Optional[str] = None
    parent: Optional[AndroidWidgetFromXML]
    children: List[AndroidWidgetFromXML]
    element_class: str
    web_driver: webdriver.Remote
    text_input_list: Optional[List[str]] = None

    def __init__(
        self,
        xml_element: ElementTree.Element,
        activity: AndroidActivity,
        driver: webdriver.Remote,
        parent_widget: Optional[AndroidWidgetFromXML] = None,
    ):
        """Initializes object.

        Args:
            xml_element: XML Element describing the widget
            activity: Activity the widget is found in.
            driver: webdriver connecting to the device the widget has been found on.
            parent_widget: Widget that is at the level directly above of this widget. Defaults to None.
        """
        self._xml_element = xml_element
        self.parent = parent_widget
        self.children = []
        self.activity = activity
        self.web_driver = driver
        self.element_class = self._xml_element.attrib["class"]

    def __getattribute__(self, item: str) -> Any:
        try:
            return super(AndroidWidgetFromXML, self).__getattribute__(item)
        except AttributeError as err:
            raise err

    @staticmethod
    def _str_to_bool(string: str) -> bool:
        return string.lower() == "true"

    def is_clickable(self) -> bool:
        return self._str_to_bool(self._xml_element.attrib["clickable"])

    def is_checkable(self) -> bool:
        return self._str_to_bool(self._xml_element.attrib["checkable"])

    def is_displayed(self) -> bool:
        return self._str_to_bool(self._xml_element.attrib["displayed"])

    def is_enabled(self) -> bool:
        return self._str_to_bool(self._xml_element.attrib["enabled"])

    def get_description(
        self, recursive: bool = True, comparison: bool = True
    ) -> str:
        """Returns description of Widget.

        Depending on the type of widget different attributes are used to generate description.
        For text input elements the order is _original_text, text, content-desc, resource-id, recursion.
        For other elements the order is text, content-desc, recursion, resource-id.
        The first value that is neither None nor the empty string is returned.

        Args:
            recursive: If True, it attempts to recursively obtain a description for the widget from its children,
                       in case none is available for the widget itself. Else the widgets description is returned.
                       Defaults to True.
            comparison: If True, it attempts to return a description that is stable over multiple iterations. This is
                       only relevant for text input fields, where the original description can be of more value
                       than the text currently put in. Else the widgets description is returned.
                       Takes precedence over recursive. Defaults to False.

        Returns:
            Description of widget.
        """
        result: Union[Set[str], str]

        if self.get_class_string() in WIDGET_INPUT_CLASSES:
            if not comparison:
                # Whenever possible don't use text in Input fields for comparisons
                # as it often changes with the fields staying the same for example due to user input.
                if self._original_text is not None:
                    # If original text has been saved, use it because the text inside the field might have changed
                    return self._original_text
                else:
                    with suppress(KeyError):
                        result = self._xml_element.attrib["text"]
                        if result:
                            return result

            # Try to detect filled and unfilled EditText fields as the same UI element
            with suppress(KeyError):
                result = self._xml_element.attrib["content-desc"]
                if result:
                    return result
            with suppress(KeyError):
                result = self._xml_element.attrib["resource-id"]
                if result:
                    return result

            if recursive:
                result = set(
                    child.get_description(recursive) for child in self.children
                )
                # Exclude the empty string
                result -= {""}

        else:
            with suppress(KeyError):
                result = self._xml_element.attrib["text"]
                if result:
                    return result
            with suppress(KeyError):
                result = self._xml_element.attrib["content-desc"]
                if result:
                    return result

            if recursive:
                result = set(
                    child.get_description(recursive) for child in self.children
                )
                # Exclude the empty string
                result -= {""}

            # An empty set also evaluates to false
            if not result:
                # resource-id is used as a last resort, because it often does not produce meaningful descriptions
                with suppress(KeyError):
                    result = self._xml_element.attrib["resource-id"]
                    if result:
                        return result

        # Return concatenation of all descriptions found (if result is an empty set, this returns the empty string)
        if recursive:
            return " ; ".join(result)

        # If no description has been found return the empty string
        return ""

    def get_class_string(self) -> str:
        return self.element_class

    def get_boundaries_on_screen(
        self,
    ) -> Optional[Tuple[Tuple[int, int], Tuple[int, int]]]:
        """Extracts boundaries of widget from data.

        Returns:
            If regex matches, top left and bottom right coordinates in the form ((x1, y1), (x2, y2)), else None.
        """
        try:
            match = re.match(
                r"\[(?P<x1>[0-9]+),(?P<y1>[0-9]+)]\[(?P<x2>[0-9]+),(?P<y2>[0-9]+)]",
                self._xml_element.attrib["bounds"],
            )
            if match:
                x1 = int(match.group("x1"))
                x2 = int(match.group("x2"))
                y1 = int(match.group("y1"))
                y2 = int(match.group("y2"))
                return (x1, y1), (x2, y2)
            return None
        except KeyError:
            return None

    def click(self) -> bool:
        """Clicks on the widget. The middle of the widget is used as target.

        Returns:
            Click successful
        """
        boundaries = self.get_boundaries_on_screen()
        if boundaries:
            (x1, y1), (x2, y2) = boundaries
            # Click in the middle of the found bounds
            x = x1 + (x2 - x1) // 2
            y = y1 + (y2 - y1) // 2
            return click_by_coordinates(self.web_driver, x, y)
        return False

    def text_input(
        self, input_str: str, hit_enter: bool = False
    ) -> Optional[str]:
        """Inputs a given string into the widget.

        Clicks on the widget and then sends keys to device.

        Args:
            input_str: String used as input.
            hit_enter: If True, hits enter after input. Defaults to True.

        Returns:
            If input action is successful, the string used as input value is returned, else None.
        """
        if self.click():
            try:
                # If there is no stored original text, save the current text there for later
                if self._original_text is None:
                    self._original_text = self._xml_element.attrib["text"]
                action_chain = ActionChains(self.web_driver)
                action_chain.send_keys(input_str)
                action_chain.perform()
                logger.debug(f'String "{input_str}" has been put in.')
                if hit_enter:
                    logger.debug("Hitting enter key")
                    self.web_driver.press_keycode(ANDROID_ENTER_KEY_CODE)

                before_sleep = self.web_driver.current_activity
                sleep(0.3)
                after_sleep = self.web_driver.current_activity
                if after_sleep != before_sleep:
                    logger.debug(
                        f'############## "{after_sleep}" != "{before_sleep}" -> sleeping after inputting text is '
                        f'necessary ############## '
                    )

                return input_str
            except RuntimeError:
                logger.debug(
                    f'An exception occurred while trying to input "{input_str}"', exc_info=True
                )
                return None
        else:
            return None

    def intelligent_text_input(self, hit_enter: bool = True) -> Optional[str]:
        """Inputs some more "intelligent" string into the widget than just random strings.

        Args:
            hit_enter: If True, hits enter after input. Defaults to True.

        Returns:
            If input action is successful, the string used as input value is returned, else None.
        """

        with suppress(KeyError):
            if "email" in self._xml_element.attrib["resource-id"]:  # Only an unreliable prototype.
                # Probably it is possible to detect email fields more reliable.
                return self.text_input(get_random_email(), hit_enter)

        if self.text_input_list is None:
            return self.random_input(hit_enter)

        if len(self.text_input_list) == 0:
            return self.random_input(hit_enter)

        with suppress(KeyError):
            if self._str_to_bool(self._xml_element.attrib["password"]):
                return self.random_input(hit_enter)

        rand_index: int = seeded_random.randint(0, len(self.text_input_list) - 1)
        input_string = self.text_input_list[rand_index].strip()
        return self.text_input(input_string, hit_enter)


# noinspection PyAbstractClass
class AndroidWidgetFromWebDriver(AndroidWidget):
    """Class for Android widgets created from WebElements.

    No current implementation is available.
    """
    # Not working code has been removed. Look into previous commit in git version history for more info
    def __init__(self) -> None:
        raise NotImplementedError


def get_interactive_elements_from_xml(
    app_model: AndroidAppModel,
    xml_and_activity: Optional[Tuple[ElementTree.Element, AndroidActivity]] = None,
) -> Tuple[List[AndroidWidgetFromXML], List[AndroidWidgetFromXML]]:
    """Returns a list of all interactive elements, that are either found on the current screen or in the supplied xml.

    Args:
        app_model: App model used for current analysis
        xml_and_activity: Tuple of XML-root-element and current activity. Defaults to None.

    Returns:
        Tuple made from list of clickable widgets and text input widgets
    """
    if not xml_and_activity:
        activity = app_model.get_current_activity()
        xml_root_elem = get_xml_source(app_model.session.appium_wd)
    else:
        xml_root_elem, activity = xml_and_activity
    if not xml_root_elem:
        return list(), list()

    root_elem = parse_xml_to_objects(xml_root_elem, activity=activity, appium_wd=app_model.session.appium_wd,
                                     text_input_list=app_model.session.text_input_list)

    def unpack_child_hierarchy_to_list(
        elem: AndroidWidgetFromXML,
    ) -> List[AndroidWidgetFromXML]:
        """Returns recursively unpacked children of elem.

        Args:
            elem: "root"-widget, whose children are returned

        Returns:
            List of all children of elem
        """
        result = [child for child in elem.children]
        for child_list in [
            unpack_child_hierarchy_to_list(child) for child in elem.children
        ]:
            result += child_list
        return result

    elements = [root_elem] + unpack_child_hierarchy_to_list(root_elem)
    clickable_widgets = [
        elem
        for elem in elements
        if elem.is_clickable()
        and elem.is_enabled()
        and elem.get_class_string() not in WIDGET_INPUT_CLASSES
    ]
    input_widgets = [
        elem
        for elem in elements
        if elem.is_enabled()
        and elem.is_displayed()
        and elem.get_class_string() in WIDGET_INPUT_CLASSES
    ]
    return clickable_widgets, input_widgets


def get_xml_source(
    appium_wd: webdriver.Remote,
) -> Optional[ElementTree.Element]:
    """Get currently visible elements as XML-hierarchy. Closes on-screen keyboard before getting elements.

    Args:
        appium_wd: webdriver connection to the device

    Returns:
        Root-XML-element if operation succeeds, else None.
    """
    try:
        # Close On-Screen Keyboard
        appium_wd.hide_keyboard()
        #response = appium_wd.execute_driver(
        #    "const source = await driver.getPageSource();return source;"
        #)
        page_source = appium_wd.page_source
        if page_source:
            root_elem = ElementTree.fromstring(page_source)
            return root_elem
        else:
            return None
    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()

def parse_xml_to_objects(
    root_element: ElementTree.Element,
    activity: AndroidActivity,
    appium_wd: webdriver.Remote,
    text_input_list: Optional[List[str]] = None
) -> AndroidWidgetFromXML:
    """Recursively parses XML-widget-hierarchy into AndroidWidgetFromXML objects maintaining hierarchy.

    Args:
        root_element: XML-root-element
        activity: Activity the widgets have been found in.
        appium_wd: webdriver connection to the device the widgets have been found on.
        text_input_list: List of words passed to all widgets to be randomly used by intelligent_text_input()

    Returns:
        root_element and its children parsed into AndroidWidgetFromXML objects
    """
    # Exclude "hierarchy" xml-object from being parsed into an AndroidWidget object
    if root_element.tag.startswith("hierarchy"):

        if len(root_element) == 1:
            return parse_xml_to_objects(
                root_element[0], activity=activity, appium_wd=appium_wd, text_input_list=text_input_list
            )
        elif len(root_element) == 2 and root_element[1].tag == "android.widget.Toast":
            # Handle situations, where an App displays a notification in form of a toast element,
            # that disappears after a short while, by ignoring the toast
            return parse_xml_to_objects(
                root_element[0], activity=activity, appium_wd=appium_wd
            )
        else:
            logger.debug("More then 3 elements, first one should be app others android")
            logger.debug(f"{[(element, element.attrib) for element in root_element]}")

            return parse_xml_to_objects(
                root_element[0], activity=activity, appium_wd=appium_wd
            )
            #raise NotImplementedError(
            #    f'Parsing xml "{root_element.tag}" objects with {len(root_element)} children '
            #    f"into python objects is not supported (yet)."
            #)

    new_root = AndroidWidgetFromXML(root_element, driver=appium_wd, activity=activity)
    new_root.text_input_list = text_input_list
    for element in root_element:
        new_element = parse_xml_to_objects(
            element, appium_wd=appium_wd, activity=activity, text_input_list=text_input_list
        )
        new_element.parent = new_root
        new_root.children.append(new_element)
    return new_root
