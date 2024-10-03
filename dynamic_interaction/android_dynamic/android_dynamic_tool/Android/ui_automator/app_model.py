from __future__ import annotations

import logging
import os
import tempfile
import warnings
from contextlib import suppress
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Set, Union, TYPE_CHECKING

from selenium.common.exceptions import ScreenshotException, WebDriverException

from ..app import AndroidActivity, AndroidAppPackage
from .gui_wrapper import (
    get_interactive_elements_from_xml,
    get_xml_source,
)
from ...helper.constants import LOGGER_BASE_NAME, TMP_ROOT

if TYPE_CHECKING:
    from .exploration_session import AndroidExplorationSession
    from .gui_wrapper import AndroidWidget

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".android.app_model")


class State:
    """Stores all information necessary for identification and comparison of a State."""
    package: AndroidAppPackage
    activity: AndroidActivity
    calling_action: Optional[Action]  # "Edge" to the previous "node"(State)
    possible_actions: List[Action]  # "Edges" to the next "nodes"(States)

    back_action: Optional[Action] = (
        None  # "Edge" pointing to the state after clicking on "back"
    )

    screenshot: Optional[str] = None

    additional_info: Dict[str, Any] = dict()

    def __init__(
            self,
            activity: AndroidActivity,
            calling_action: Optional[Action],
    ):
        """Initializes state with activity the state is taken from and calling action if available.

        Args:
            activity: Activity the state has been collected in.
            calling_action: The initial calling action if known. None for initial state or if unknown.
        """
        self.package = activity.package
        self.activity = activity
        self.calling_action = calling_action
        self.possible_actions = list()

    def __eq__(self, other: object) -> bool:
        # Don't compare back_action and calling_action as these are only set correctly for already existing states.
        # Don't compare screenshot, because the path can only be equal for the same instance of state.
        if isinstance(other, State):
            #print("_____________")
            #print(f" state: {self.activity == other.activity}")
            #print(set(self.possible_actions) == set(other.possible_actions) )
            #print("_____________")
            return (
                    self.activity == other.activity
                    and set(self.possible_actions) == set(other.possible_actions)
            )
        return False

    def __str__(self) -> str:
        if self.back_action:
            actions = self.possible_actions + [self.back_action]
        else:
            actions = self.possible_actions
        return f"{str(self.activity)}:{str(actions)}"


class Action:
    """Encapsulates all information available about an Action and enables interaction."""
    origin: State
    next_state: Optional[State] = None

    package: AndroidAppPackage
    activity: AndroidActivity
    ui_element: AndroidWidget

    score: float = 0
    executed: bool = False
    execution_function: Optional[Callable] = None
    execution_kwargs: Optional[Dict[str, Any]] = None

    def __init__(
            self,
            package: AndroidAppPackage,
            activity: AndroidActivity,
            ui_element: Optional[AndroidWidget],
            origin: State,
            execution_function: Optional[Callable] = None,
            execution_kwargs: Optional[Dict[str, Any]] = None,
    ):
        """ Initializes action.

        Args:
            package: Package the action has been found in.
            activity: Activity the action has been found in.
            ui_element: UI-Element that is encapsulated by this action.
            origin: State the action has been found in.
            execution_function: If applicable, the function that can do interaction with the ui-element.
                               Defaults to None. The function should return success as bool or str (empty string for
                                failure).
            execution_kwargs: If applicable, the keyword-arguments necessary to execute execution_function as a
                             dictionary. Defaults to None.
        """
        self.package = package
        self.activity = activity
        self.ui_element = ui_element
        self.origin = origin
        self.execution_function = execution_function
        self.execution_kwargs = execution_kwargs

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return (
                    self.activity == other.activity and self.ui_element == other.ui_element
            )
        return False

    def __hash__(self) -> int:
        return hash((hash(self.activity), self.ui_element))

    def execute(self) -> Union[bool, str]:
        """Interacts with the ui_element by executing the execution_function with the execution_kwargs if supplied.

        Returns:
            Return value of the execution_function

        Raises:
            NotImplementedError: If no execution function has been supplied.
        """
        if not self.execution_function:
            raise NotImplementedError(
                "A callable has to be provided as execution function in order for the action to be executable!"
            )
        if self.execution_kwargs:
            self.executed = self.execution_function(**self.execution_kwargs)
        else:
            self.executed = self.execution_function()
        sleep(0.3)
        return self.executed

    def __str__(self) -> str:
        return f"Action(ui_element={str(self.ui_element)}, executed={self.executed})"


class AndroidAppModel:
    """Builds a model of the visited portions of the app."""
    session: AndroidExplorationSession
    initial_state: State
    current_state: State
    all_states: List[State]
    activities: Set[AndroidActivity]
    packages: Set[AndroidAppPackage]

    def __init__(self, session: AndroidExplorationSession):
        """Initializes app_model with session and collects initial state.

        Args:
            session: AndroidExplorationSession used to explore the app.
        """
        self.activities = set()
        self.packages = set()
        self.session = session
        self.initial_state = State(
            activity=self.get_current_activity(),
            calling_action=None,
        )
        self.initial_state.additional_info["xml_root"] = get_xml_source(appium_wd=self.session.appium_wd)
        self.initial_state.possible_actions = self._get_available_actions(
            self.initial_state
        )
        self.initial_state.screenshot = self.take_screenshot_as_png()
        self.current_state = self.initial_state
        self.all_states = [self.initial_state]

    def go_back(self) -> State:
        """Click back and set current state to resulting state.

        Returns:
            Resulting state.
        """
        if not self.current_state.back_action:
            self.current_state.back_action = Action(
                package=self.get_current_package(),
                activity=self.get_current_activity(),
                ui_element=None,
                origin=self.current_state,
                execution_function=self.session.appium_wd.back,
            )

        self.current_state.back_action.execute()
        new_state = State(
            activity=self.get_current_activity(),
            calling_action=self.current_state.back_action,
        )
        new_state.additional_info["xml_root"] = get_xml_source(appium_wd=self.session.appium_wd)
        new_state.possible_actions = self._get_available_actions(origin=new_state)
        new_state.screenshot = self.take_screenshot_as_png()

        if (
                self.current_state.back_action.next_state
                and new_state == self.current_state.back_action.next_state
        ):
            # If we have been in this state before and have clicked back before, it is likely that we'll end in the
            # same state as before after clicking back again
            self.current_state = self.current_state.back_action.next_state
        elif (
                self.current_state.calling_action
                and new_state == self.current_state.calling_action.origin
        ):
            # It is likely that clicking back leads us to the previous state
            self.current_state.back_action.next_state = (
                self.current_state.calling_action.origin
            )
            self.current_state = self.current_state.calling_action.origin
        elif new_state != self.current_state:
            new_state = self._add_new_state(new_state)
            self.current_state.back_action.next_state = new_state
            self.current_state = new_state
        return self.current_state

    def return_to_app(self) -> None:
        """Attempts to return to the app being explored at the location closest to the one we left the app from.
        Searches the app model for the last state that is still located in the app to be explored.
        """
        target_package = AndroidAppPackage(name=self.session.app.app_package)
        state = self.current_state
        while state.package != target_package:
            # Search for the most recent state that was still in the app under test
            if state.calling_action and state.calling_action.origin:
                state = state.calling_action.origin
            else:
                # If there is no previous state to be found stop search and use initial state
                state = None
                break

        target_activity = None
        if state:
            target_activity = state.activity
        elif self.session.app.launch_activity:
            target_activity_name = self.session.app.launch_activity
            target_activity = AndroidActivity(
                package=target_package, name=target_activity_name
            )
        elif self.session.app.main_activities:
            target_activity_names = [
                activity
                for activity in self.session.app.main_activities
                if activity.startswith(target_package.name)
            ]
            if target_activity_names:
                target_activity = AndroidActivity(
                    package=target_package, name=target_activity_names[0]
                )
        if not target_activity:
            target_activity = self.initial_state.activity

        try:
            # Activities can only be started directly, if a special "exported" flag is set to true.
            # We are not checking this, therefore this can lead to failures
            logger.info(
                f'Trying to return to app by starting the following activity (1/2): "{str(target_activity)}"'
            )

            if not self.session.device.start_activity(target_activity.package.name, target_activity.name):
                logger.debug("could not start activity, starting default one")
                if self.session.app_starter:
                    self.session.app_starter.start()

                current_activity = self.get_current_activity()
                if current_activity.package.name != self.session.app.app_package:
                    self.session.device.start_app(self.session.app)


        except WebDriverException:
            current_activity = self.get_current_activity()
            if current_activity.package.name == self.session.app.app_package:
                logger.debug(
                    f"The app started with an unexpected activity:"
                    f" {current_activity.name} instead of {target_activity.name}. Try to continue anyway..."
                )
            else:
                logger.debug(
                    f'Restarting failed, because of the following error:', exc_info=True
                )
                if (
                        target_activity != self.initial_state.activity
                        and self.initial_state.activity.package.name
                        == self.session.app.app_package
                ):
                    target_activity = self.initial_state.activity
                logger.info(
                    f'Trying again to return to app by starting the following activity (2/2): "{str(target_activity)}"'
                )

                if not self.session.device.start_activity(target_activity.package.name, target_activity.name):
                    logger.debug("could not start activity, starting default one")
                    if self.session.app_starter:
                        self.session.app_starter.start()
                    current_activity = self.get_current_activity()
                    if current_activity.package.name != self.session.app.app_package:
                        self.session.device.start_app(self.session.app)


        new_state = State(
            activity=self.get_current_activity(),
            calling_action=None,
        )
        new_state.additional_info["xml_root"] = get_xml_source(appium_wd=self.session.appium_wd)
        new_state.possible_actions = self._get_available_actions(origin=new_state)
        new_state.screenshot = self.take_screenshot_as_png()

        new_state = self._add_new_state(new_state=new_state)
        self.current_state = new_state

    def _add_new_state(self, new_state: State) -> State:
        """Adds new state to the list of encountered states. If the state has been encountered before, the already
        known state is used and returned.

        Args:
            new_state: State to be added.

        Returns:
            Added/Reused state
        """
        # Try not to create duplicate states, but instead find backwards pointing links
        for state in self.all_states:
            if new_state == state:
                logger.debug("Current state has already been encountered before")
                return state
        self.all_states.append(new_state)
        print(len(self.all_states))
        return new_state

    def collect_next_state(self, calling_action: Action) -> State:
        """Collects the next state that is entered after calling_action has been executed.

        Args:
            calling_action: The action that has been executed to attempt reaching the next state.

        Returns:
            The state that the app is currently in
        """
        if calling_action.origin != self.current_state:
            warnings.warn(
                "This should not happen! If you do this, there might be an inconsistency in the tree structure. "
                "Please check, whether this is correct."
            )

        new_state = State(
            activity=self.get_current_activity(),
            calling_action=calling_action,
        )
        new_state.additional_info["xml_root"] = get_xml_source(appium_wd=self.session.appium_wd)
        new_state.possible_actions = self._get_available_actions(origin=new_state)

        new_state = self._add_new_state(new_state)
        calling_action.next_state = new_state

        new_state.screenshot = self.take_screenshot_as_png()
        self.current_state = new_state

        return new_state

    def take_screenshot_as_png(self) -> Optional[str]:
        """Attempts to take screenshot of device screen as PNG and stores it to temporary directory.
        If the screenshot fails to be taken due to insufficient permissions or similar, None is returned.

        If an app specifies FLAG_SECURE=True, Android prevents Appium from taking a screenshot.

        Returns:
            Path to screenshot as string, None if taking screenshot failed.
        """
        try:
            file_handle, path = tempfile.mkstemp(suffix=".png", dir=TMP_ROOT)
            self.session.appium_wd.save_screenshot(path)
            with suppress(OSError):  # save_screenshot() keeps the file handle open. In case of the analysis of many
                # this leads to the error "to many open files"
                os.close(file_handle)
            # with open(path, mode="wb") as file:
            #    file.write(self.session.appium_wd.get_screenshot_as_png())
            # os.close(file_handle)
            return path

        except ScreenshotException:
            # Sometimes taking a screenshot fails, because of special settings by the app, e.g. the SECURE_FLAG
            # This issue could be resolved by using frida for screenshots.
            return None

    def refresh_state(self) -> bool:
        """Checks whether the current state is still on screen. Updates current state if it has changed.
        (This is useful for situations with loading screens, where the effect of the previous action
        is not immediately visible)

        Returns:
            Has state changed
        """
        new_state = State(
            activity=self.get_current_activity(),
            calling_action=self.current_state.calling_action,
        )
        new_state.additional_info["xml_root"] = get_xml_source(appium_wd=self.session.appium_wd)
        new_state.possible_actions = self._get_available_actions(origin=new_state)

        if new_state != self.current_state:
            new_state = self._add_new_state(new_state)
            if self.current_state.calling_action:
                self.current_state.calling_action.next_state = new_state
            new_state.screenshot = self.take_screenshot_as_png()
            self.current_state = new_state
            return True
        return False

    def has_state_changed(self) -> bool:
        """Checks whether the screen has changed or is still displaying the current state

        Returns:
        Has state changed

        """
        new_state = State(
            activity=self.get_current_activity(),
            calling_action=None,
        )
        new_state.possible_actions = self._get_available_actions(origin=new_state)

        return new_state == self.current_state

    def get_untried_actions(self) -> List[Action]:
        """Returns all possible actions in the current state that have not been executed yet

        Returns:
            List of all actions that have not been executed.
        """
        if self.current_state.possible_actions:
            return [
                action
                for action in self.current_state.possible_actions
                if not action.executed
            ]
        return []

    def get_current_package(self) -> AndroidAppPackage:
        """Obtain the package of the currently visible App and add it to the set of seen packages in the app_model.

        Returns:
            Package of the currently visible App.
        """
        package_name = self.session.appium_wd.current_package
        for package in self.packages:
            if package.name == package_name:
                return package
        package = AndroidAppPackage(name=package_name)
        self.packages.add(package)
        return package

    def get_current_activity(self) -> AndroidActivity:
        """Obtain the activity of the currently visible App and add it to the set of seen activities in the app_model.

        Returns:
            Activity of the currently visible App.
        """
        package = self.get_current_package()
        activity_name = self.session.appium_wd.current_activity
        for activity in self.activities:
            if activity.name == activity_name and activity.package == package:
                return activity
        activity = AndroidActivity(name=activity_name, package=package)

        package.activities.add(activity)
        self.activities.add(activity)
        return activity

    def _get_available_actions(self, origin: State) -> List[Action]:
        """Obtains all available actions currently visible on screen/stored in the xml belonging to origin.

        Args:
            origin: State the actions are found in.

        Returns:
            List of actions found in State origin.
        """
        if "xml_root" in origin.additional_info:
            xml_root = origin.additional_info["xml_root"]
            activity = origin.activity
            xml_and_activity = (xml_root, activity)
        else:
            xml_and_activity = None
        clickable_ui_elements, text_input_elements = get_interactive_elements_from_xml(
            app_model=self, xml_and_activity=xml_and_activity
        )
        actions = [
            Action(
                package=origin.package,
                activity=origin.activity,
                ui_element=element,
                origin=origin,
                execution_function=element.click,
            )
            for element in clickable_ui_elements
        ]
        actions.extend(
            [
                Action(
                    package=origin.package,
                    activity=origin.activity,
                    ui_element=element,
                    origin=origin,
                    execution_function=element.intelligent_text_input,
                )
                for element in text_input_elements
            ]
        )
        actual_current_activity = self.get_current_activity()
        if actual_current_activity != origin.activity:
            logger.debug(
                "INCONSISTENCY DETECTED: actual_current_activity != origin.activity:\n"
                f"{actual_current_activity} != {origin.activity}"
            )
            pass

        return actions
