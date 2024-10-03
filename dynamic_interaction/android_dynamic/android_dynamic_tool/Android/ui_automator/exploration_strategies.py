from __future__ import annotations

from ...helper.seeded_random import seeded_random
import logging
from time import sleep
from typing import Optional

from .app_model import Action
from .constants import (ANDROID_CHROME_PACKAGE_NAME,
                        ANDROID_SYSTEM_DIALOG_ACTIVITIES,
                        WIDGET_INPUT_CLASSES)
from .exploration_session import AndroidExplorationSession
from ...common.exploration_strategies import ExplorationStrategy
from ...helper.constants import LOGGER_BASE_NAME, EMULATOR_ANDROID_DEFAULT_LAUNCHER_PACKAGE_NAMES
from ...helper.storage_helper import StorageHelper
from selenium.common.exceptions import WebDriverException

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".exploration-strategies")


class AndroidExplorationStrategy(ExplorationStrategy):
    """Handles app state analysis and decides on steps to take next."""
    session: AndroidExplorationSession

    # https://developer.android.com/reference/android/widget/package-summary

    results_helper: StorageHelper.AnalysisResultsHelper

    def __init__(self, session: AndroidExplorationSession):
        """Initializes with session.

        Args:
            session: Session used for exploration.
        """
        super(AndroidExplorationStrategy, self).__init__(session)

    def explore(self, results_helper: StorageHelper.AnalysisResultsHelper, steps: int = 1000) -> None:
        """Explores the application set in session for x steps. Stores actions and info using results_helper.

        Args:
            results_helper: Helper used to store intermediate results/steps.
            steps: Number of exploration steps.
        """
        logger.info("Starting exploration for {} steps".format(steps))
        self.results_helper = results_helper

        for i in range(1, steps + 1):
            try:
                self.session.benchmark.before_step(step=i)
                self.results_helper.add_to_step(
                    step=i,
                    state=self.session.app_model.current_state,
                    screenshot=self.session.app_model.take_screenshot_as_png(),
                )
                self.execute_next_step(step=i)
                self.session.benchmark.after_step(step=i)
            except WebDriverException:
                # fixme restart selenium
                # restart selenium
                pass

        self.results_helper.add_to_step(
            step=steps + 1,
            state=self.session.app_model.current_state,
            screenshot=self.session.app_model.take_screenshot_as_png(),
        )

        unique_actions_seen = []
        for state in self.session.app_model.all_states:
            # Assuming that state identification is perfect, each state and therefore each action should only be
            # found once
            unique_actions_seen += state.possible_actions

        self.results_helper.add_general_statistics(
            packages_visited=[package for package in self.session.app_model.packages],
            activities_visited=[
                activity for activity in self.session.app_model.activities
            ],
            unique_states=self.session.app_model.all_states,
            unique_actions_seen=unique_actions_seen,
        )

    def score_possible_actions(self) -> Optional[Action]:
        """Scores possible actions and returns the highest scoring, if it can select a suitable action.

        Raises:
            NotImplementedError: Has to be implemented by subclass.
        """
        raise NotImplementedError

    def execute_next_step(self, step: int) -> None:
        """Executes the next step.

        Uses score_possible_actions to select Action to execute. Executes the Action and refreshes State.
        Stores information for step using results_helper

        Args:
            step: Index of the step, used to select correct step in results_helper.
        """
        app_model = self.session.app_model

        if self.session.device.emulator is not None:
            launcher = self.session.device.emulator.launcher_package_name
        else:
            launcher = EMULATOR_ANDROID_DEFAULT_LAUNCHER_PACKAGE_NAMES[self.session.device.platform_version]

        if (
                app_model.current_state.activity.name
                != self.session.appium_wd.current_activity
        ):
            logger.debug(
                f"INCONSISTENCY DETECTED: app_model.app_model.current_state != actual state: "
                f'"{app_model.current_state.activity.name} != {self.session.appium_wd.current_activity}"\n'
                f"Refreshing state."
            )
            app_model.refresh_state()
            self.results_helper.increase_state_refresh_count()

        if app_model.current_state.package.name != self.session.app.app_package:
            # Handle links to Chrome
            if app_model.current_state.package.name == ANDROID_CHROME_PACKAGE_NAME:
                logger.debug(
                    "Entered Chrome app, even though it's not the app under test, "
                    "trying to return to the actual app under test, by clicking back."
                )
                app_model.go_back()
                self.results_helper.add_to_step(step=step, back_action=True)
                return
            # Handle home screen
            elif app_model.current_state.package.name == launcher:
                logger.debug(
                    "Returned to home screen, even though analysis wasn't finished. "
                    "Trying to return to the actual app under test."
                )
                app_model.return_to_app()
                self.results_helper.add_to_step(step=step, return_action=True)
                return
            # Handle share dialog
            elif app_model.current_state.activity in ANDROID_SYSTEM_DIALOG_ACTIVITIES:
                logger.debug(
                    "Entered share dialog, trying to leave it by clicking back"
                )
                app_model.go_back()
                self.results_helper.add_to_step(step=step, back_action=True)
                return
            else:
                logger.debug(
                    "Left app, deciding randomly whether to return or continue for one step"
                )
                if seeded_random.choice([True, True, False]):  # Chance of 2/3 to return to app
                    logger.debug("Trying to return to it by clicking back.")
                    app_model.go_back()
                    self.results_helper.add_to_step(step=step, back_action=True)
                    if (
                            app_model.current_state.package.name
                            != self.session.app.app_package
                    ):
                        logger.debug("Clicking back was not sufficient.")
                        app_model.return_to_app()
                        self.results_helper.add_to_step(step=step, return_action=True)
                    return
                else:
                    logger.debug("Continuing exploration")

        self.results_helper.add_general_statistics(
            actions_seen=app_model.current_state.possible_actions
        )
        selected_action = self.score_possible_actions()

        if not selected_action:
            if app_model.current_state != app_model.initial_state:
                logger.debug('No element selected, clicking "back" button')
                app_model.go_back()
                self.results_helper.add_to_step(step=step, back_action=True)
            else:
                # Don't go back if we never left the initial state, could be an indicator for a loading screen
                logger.debug(
                    "No actionable elements found, maybe we are in a loading screen. "
                    "Sleeping a second and trying again."
                )
                sleep(1)
                app_model.refresh_state()
                self.results_helper.increase_state_refresh_count()
            return

        if selected_action.ui_element:
            logger.debug(
                f'Selected "{selected_action.ui_element.get_class_string()}" element '
                f'"{selected_action.ui_element.get_description()}"'
                f" with score {selected_action.score}"
                f" to interact with"
            )
        else:
            logger.debug(
                f'Selected action "{str(selected_action)}" with score {selected_action.score} to interact with.'
            )
        if not selected_action.execute():
            logger.debug(
                "Failed to interact with previously selected element, refreshing state"
            )

            # Do not increase refreshed_state count here, because this is used instead of collect_next_state
            app_model.refresh_state()
        else:
            logger.debug(
                "Interaction with previously selected element succeeded, entering next state"
            )
            app_model.collect_next_state(selected_action)
        self.results_helper.add_to_step(step=step, action=selected_action)


class AndroidRandomButtonExplorationStrategy(AndroidExplorationStrategy):
    """This strategy only takes into account, whether or not an element is clickable.
    Actions may be repeated."""

    def score_possible_actions(
            self,
    ) -> Optional[Action]:
        """Scores possible actions randomly and returns the highest scoring.

        Returns:
            Highest scoring action if an interactable action is found. Else None is returned.
        """
        selected_action = None

        available_actions = self.session.app_model.current_state.possible_actions

        for action in available_actions:
            if action.ui_element and action.ui_element.get_class_string() in WIDGET_INPUT_CLASSES:
                action.score = seeded_random.randint(0, 1000)
            elif action.ui_element and action.ui_element.is_clickable() and action.ui_element.is_enabled():
                action.score = seeded_random.randint(0, 1000)
            else:
                action.score = -1

            if not selected_action or action.score > selected_action.score:
                selected_action = action

        if not selected_action or selected_action.score < 0:
            logger.info("No possible action found")
            return None

        return selected_action


class AndroidIntelligentRandomButtonExplorationStrategy(AndroidExplorationStrategy):
    """Do "intelligent" random exploration by filtering out elements that have "bad" words in their description
    Also lower score of actions that have already been executed."""

    MAX_RETRIES = 2

    SKIP_THESE_WORDS = [
        "login",
        "account",
        "sign in",
        "sign up",
        "voice search",
        "cancel",
        "open camera",
        "deny",
        "do not allow",
        "password",
    ]

    GOOD_WORDS = [
        # "ok",  # False positives like "cookie"/"Facebook"!!!!!
        "okay",
        "accept",
        "continue",
        "next",
        "skip_ad",
        "skip",
        "allow",
    ]

    def score_possible_actions(
            self,
            retry: int = 0,
    ) -> Optional[Action]:
        """Scores possible actions and returns the highest scoring, if it can select a suitable action.
        Attempts refreshing the state for a maximum of MAX_RETRIES times, if no action can be selected.

        Args:
            retry: Number of the current retry. Defaults to 0 for initial attempt.
                   Should not be necessary to set.

        Returns:
            Highest scoring action if a suitable action is found. Else None is returned.
        """
        selected_action = None

        available_actions = self.session.app_model.current_state.possible_actions

        for action in available_actions:
            if action.ui_element.get_class_string() in WIDGET_INPUT_CLASSES:
                # Increase score of unfilled input classes, reduce score of filled input classes
                action.score = seeded_random.randint(0, 1000) * (
                    2 if not action.executed else 0.2
                )
            elif action.ui_element.is_clickable() and action.ui_element.is_enabled():
                action.score = seeded_random.randint(0, 1000)

                desc = action.ui_element.get_description().lower()
                if desc == "":
                    action.score = 0
                else:
                    for word in self.SKIP_THESE_WORDS:
                        if word in desc:
                            # Only tap these elements, if there is nothing else left to tap
                            action.score = -1
                            logger.debug(
                                f'Element skipped because of description "{action.ui_element.get_description()}"'
                            )
                            break
                    for word in self.GOOD_WORDS:
                        if word in desc:
                            # Only tap these elements, if there is nothing else left to tap
                            action.score += 500
                            logger.debug(
                                f'Element ranked higher because of description "{desc}"'
                            )
                            break

                if action.executed:
                    # "Non-Input" Actions that have already been executed should be less likely to be executed again
                    action.score *= 0.3
            else:
                action.score = -2

        if available_actions:
            # Sort by score in descending order
            available_actions.sort(key=lambda _action: _action.score, reverse=True)

            # Take highest ranked action with score >= 0
            index = 0
            selected_action = available_actions[index]
            index += 1
            while selected_action.score < 0 and index < len(available_actions):
                selected_action = available_actions[index]
                index += 1

        if not selected_action or selected_action.score <= 0:
            while retry < self.MAX_RETRIES:
                retry += 1
                logger.info(
                    "No interesting actions found, sleeping for a second and refreshing state"
                )
                sleep(1)
                if not self.session.app_model.refresh_state():
                    logger.debug("State has not changed")
                    continue
                logger.debug(
                    "State has changed. Trying to find suitable action in newly possible actions"
                )

                return self.score_possible_actions(retry=retry)

            return None

        return selected_action




# extend WIDGET_INPUT_CLASSES

class DFSStrategy(AndroidExplorationStrategy):
    """Depth-first search exploring views in detail before switching to different ones."""

    # set values for input fields, press buttons DFS manner
    def score_possible_actions(
            self,
            retry: int = 0,
    ) -> Optional[Action]:

        available_actions: List[Action] = self.session.app_model.current_state.possible_actions

        non_executed_clickable: Set[Action] = set()
        non_executed_other_actions: Set[Action] = set()
        for action in available_actions:
            print(action)
        for action in available_actions:
            if action.ui_element.get_class_string() in WIDGET_INPUT_CLASSES and not action.executed:
                return actio
            elif action.ui_element.is_clickable() and action.ui_element.is_enabled() and not action.executed:
                non_executed_clickable.add(action)
            elif not action.executed:
                non_executed_other_actions.add(action)

        for action in non_executed_clickable:
            return action

        for action in non_executed_other_actions:
            return action

        return None # Go back to previous screen, since all actions are explored