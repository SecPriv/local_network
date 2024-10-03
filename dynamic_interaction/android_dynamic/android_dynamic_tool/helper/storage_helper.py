from __future__ import annotations

import csv
import git
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field, is_dataclass
from logging import FileHandler, getLogger
from pathlib import Path
from shutil import move
from typing import TYPE_CHECKING

from ..Android.app import AndroidActivity, AndroidApp, AndroidAppPackage
import android_dynamic_tool.Android.certificate_pinning as certificate_pinning
from ..Android.ui_automator.app_model import Action, State
from ..Android.ui_automator.gui_wrapper import AndroidWidget
from .constants import LOGGER_BASE_NAME, TMP_ROOT

if TYPE_CHECKING:
    from logging import Formatter, Logger
    from argparse import Namespace
    from typing import Callable, Dict, List, Optional, Union, Any

META_CSV_FIELD_NAMES = [
    "name",
    "package_name",
    "version_string",
    "version_code",
    "sha256_hash",
    "apk_path",
    "main_activities",
    "activities",
]
DELIMITER = ";"  # Use semicolon to be able to print out lists

logger = getLogger(LOGGER_BASE_NAME + ".storage_helper")


class StorageHelper:
    """Provides a unified interface for using storage."""
    root_directory: Path
    logging: _LoggingHelper
    results: AnalysisResultsHelper
    _meta_data: List[AndroidApp]
    _meta_data_file_path: Path

    def __init__(
            self,
            output_dir: Path,
            base_logger: Logger,
            log_level: int,
            log_formatter: Formatter,
    ):
        """Initializes objects and sub-objects for logging and results. Creates metadata.csv file.

        Args:
            output_dir: Path to directory all output is to be written to. The directory must exist.
            base_logger: Logger instance functioning as the base logger.
            log_level: Log level as represented by logging module.
            log_formatter: Formatter instance according to which every output is formatted.


        Raises:
            NotADirectoryError: If output_dir is not an existing directory.
        """
        self.root_directory = output_dir
        if not self.root_directory.is_dir():
            NotADirectoryError(f"{self.root_directory} does either not exist or is not a directory.")

        self.logging = self._LoggingHelper(
            storage_helper=self,
            base_logger=base_logger,
            log_level=log_level,
            log_formatter=log_formatter,
        )
        self.results = self.AnalysisResultsHelper(storage_helper=self)

        self._meta_data = []

        # Create metadata file
        self._meta_data_file_path = self.root_directory / "metadata.csv"
        with self._meta_data_file_path.open(mode="w", newline="") as file:
            csv.DictWriter(
                file, fieldnames=META_CSV_FIELD_NAMES, delimiter=DELIMITER
            ).writeheader()

        if not self.get_downloads_path().is_dir():
            os.mkdir(self.get_downloads_path())

    def store_execution_details(self, args: Optional[Namespace]) -> None:
        details: dict = dict()
        if args:
            details['cli_args'] = vars(args)
        details['version'] = {'commit': self.__class__.get_tool_version()}
        with (self.root_directory / "run.json").open(mode="w") as details_file:
            json.dump(details, details_file, indent=3, default=str)

    @staticmethod
    def get_tool_version() -> str:
        #repo = git.Repo(search_parent_directories=True)
        #sha_version = repo.head.object.hexsha
        return "own_version"

    def store_metadata_and_apk(
            self, android_app: AndroidApp, move_apk: bool = False
    ) -> None:
        """Store metadata and APK of android_app in output directory.

        Metadata is stored to metadata.csv

        Args:
            android_app: App, whose metadata and APK is to be stored.
            move_apk: If True, the APK is moved to the output folder, else it is not moved. Defaults to False
                     Useful if APK is located in temporary directory
        """
        # Check if metadata is already there
        if android_app in self._meta_data:
            return

        self._meta_data.append(android_app)

        app_dir = self._get_app_dir(android_app)

        # Move apk file to persistent directory if requested
        if move_apk:
            apk_store_path = app_dir / (android_app.app_package + ".apk")
            if not apk_store_path.is_file() and android_app.apk_path:
                logger.debug(f"Moving {android_app.apk_path} to {apk_store_path}")
                move(str(android_app.apk_path), apk_store_path)
                android_app.apk_path = apk_store_path

        # Store metadata
        meta_data_dict = dict(
            name=android_app.name,
            apk_path=android_app.apk_path.name,
            package_name=android_app.app_package,
            version_string=android_app.version_string,
            version_code=android_app.version_code,
            main_activities=list(android_app.main_activities),
            activities=list(android_app.activities),
            sha256_hash=android_app.apk_hash,
        )

        with self._meta_data_file_path.open(mode="a", newline="") as file:
            csv.DictWriter(
                file, fieldnames=META_CSV_FIELD_NAMES, delimiter=DELIMITER
            ).writerow(meta_data_dict)

    class _LoggingHelper:
        """Helper for all logging related issues."""
        log_level: int
        log_formatter: Formatter
        root_directory: Path
        _log_handlers: Dict[AndroidApp, FileHandler]
        _base_logger: Logger
        _get_app_dir: Callable

        def __init__(
                self,
                storage_helper: StorageHelper,
                base_logger: Logger,
                log_level: int,
                log_formatter: Formatter,
        ):
            """Initializes LoggingHelper.

            Args:
                storage_helper: Instance of StorageHelper parent object.
                base_logger: Logger instance functioning as the base logger.
                log_level: Log level as represented by logging module.
                log_formatter: Formatter instance according to which every output is formatted.
            """
            self.root_directory = storage_helper.root_directory
            self._get_app_dir = storage_helper._get_app_dir
            self._base_logger = base_logger
            self.log_level = log_level
            self.log_formatter = log_formatter

        def add_log_file_handler(self) -> FileHandler:
            """Returns FileHandler storing log file in temp directory and adds it to the base logger instance.

            Returns:
                FileHandler storing log file in temp directory.
            """
            _, temp_log_file_path = tempfile.mkstemp(suffix=".log", dir=TMP_ROOT)
            temp_log_handler = FileHandler(temp_log_file_path)
            temp_log_handler.setLevel(1)
            temp_log_handler.setFormatter(self.log_formatter)

            self._base_logger.addHandler(temp_log_handler)

            return temp_log_handler

        def close_log_file_handler(
                self,
                handler: FileHandler,
                android_app: Optional[AndroidApp],
                prefix: str = ""
        ) -> None:
            """Closes given logfile-handler and removes it from base-logger. Moves log file to output directory.

            If a logfile of the same name already exists in the destination, the name is randomized.

            Args:
                handler: Logfile-handler that is to be closed.
                android_app: AndroidApp the logfile belongs to. If set the logfile is moved into the app folder.
                prefix: Optional prefix put before the file name of the log.
            """
            # Remove handler from base logger and move log file to app directory or
            # base output directory if no android app is given
            # Log file name is preceded by prefix, if given
            self._base_logger.removeHandler(handler)

            # Ensure that file is completely written to file
            handler.flush()
            handler.close()

            temp_log_file_path = Path(handler.baseFilename)

            if not android_app:
                log_file_path = self.root_directory / (prefix + temp_log_file_path.name)
            else:
                app_dir = self._get_app_dir(android_app)
                log_file_path = app_dir / f"{prefix}analysis.log"

                if log_file_path.exists():
                    # Choose a name that does not exist
                    log_file_path = (
                            app_dir / f"{prefix}analysis-{temp_log_file_path.name}"
                    )
            if str(temp_log_file_path):
                move(str(temp_log_file_path), log_file_path)

    class AnalysisResultsHelper:
        """Helper for all issues relating to analysis results."""
        storage_helper: StorageHelper
        root_directory: Path
        stats: Stats
        _get_app_dir: Callable
        _logger: Logger

        @dataclass
        class Step:
            """Class holding all data pertaining to an analysis step."""
            step_number: int
            state_at_start: Optional[State] = None
            executed_action: Optional[Action] = None
            special_action: Optional[str] = None
            action_result: Union[bool, str, None] = None
            screenshot: Optional[str] = None

        @dataclass
        class Stats:
            """Class holding all data regarding the whole analysis."""
            steps: Union[Dict[int, StorageHelper.AnalysisResultsHelper.Step],
                         List[StorageHelper.AnalysisResultsHelper.Step]] \
                = field(default_factory=dict)
            actions_seen: List[Action] = field(default_factory=list)
            unique_states: List[State] = field(default_factory=list)
            packages_visited: List[AndroidAppPackage] = field(default_factory=list)
            activities_visited: List[AndroidActivity] = field(default_factory=list)
            unique_actions_seen: List[Action] = field(default_factory=list)
            state_refresh_count: int = 0
            app_metadata: Optional[AndroidApp] = None
            certificate_pinning_alerts: int = 0
            api_calls: Dict[str, int] = field(default_factory=dict)
            content_uri_requests: Dict[str, Dict[str, int]] = field(default_factory=dict)
            file_access_log: Dict[str, Dict[str, Dict[str, int]]] = field(default_factory=dict)

        def __init__(self, storage_helper: StorageHelper):
            """Initializes AnalysisResultsHelper

            Args:
                storage_helper: Instance of StorageHelper parent object.
            """
            self.storage_helper = storage_helper
            self.root_directory = storage_helper.root_directory
            self._get_app_dir = storage_helper._get_app_dir
            self.stats = self.Stats()
            self._logger = logging.getLogger(LOGGER_BASE_NAME + ".helper.storage.analysis_results")

        def reset(self) -> None:
            """Resets all statistics."""
            self.stats = self.Stats()

        @staticmethod
        def _json_encoding(
                obj: Union[Step, Stats, State, AndroidActivity, AndroidAppPackage, Action, AndroidWidget, AndroidApp],
        ) -> Union[str, Dict[str, Any], List[object]]:
            """Returns json encodable representation of obj.

            Args:
                obj: Object that is to be encoded

            Returns:
                Representation of obj that is json-encodable

            Raises:
                TypeError: If type of input cannot be encoded.
            """
            if isinstance(obj, AndroidActivity):
                # Avoid circular reference by removing AndroidAppPackage from serialized version
                return str(obj)
            if is_dataclass(obj):  # Step, Stats, AndroidAppPackage
                return obj.__dict__
            if isinstance(obj, State):
                # Additional_info dict, back_action and screenshot are skipped here
                return dict(
                    package=obj.package.name,
                    activity=obj.activity,
                    initial_calling_action=obj.calling_action,
                    possible_actions=obj.possible_actions,
                    state_id=(obj.state_id if hasattr(obj, "state_id") else None)
                )
            if isinstance(obj, Action):
                # origin and next_state are skipped to avoid infinite loops
                # Score, executed are skipped as it may change over the course of a run
                # Serializing execution_function and _kwargs does not make sense
                return dict(
                    package=obj.package.name,
                    activity=obj.activity,
                    ui_element=obj.ui_element,
                )
            if isinstance(obj, AndroidWidget):
                _dict = dict(
                    activity=obj.activity,
                    clickable=obj.is_clickable(),
                    checkable=obj.is_checkable(),
                    displayed=obj.is_displayed(),
                    enabled=obj.is_enabled(),
                    desc=obj.get_description(recursive=False),
                    recursive_desc=obj.get_description(),
                )

                bounds = obj.get_boundaries_on_screen()
                if bounds:
                    (x1, y1), (x2, y2) = bounds
                    _dict["bounds_on_screen"] = dict(x1=x1, y1=y1, x2=x2, y2=y2)
                _dict["class"] = obj.get_class_string()
                return _dict
            if isinstance(obj, AndroidApp):
                return dict(
                    name=obj.name,
                    apk_path=obj.apk_path,
                    app_package=obj.app_package,
                    launch_activity=obj.launch_activity,
                    version_string=obj.version_string,
                    version_code=obj.version_code,
                    main_activities=obj.main_activities,
                    activities=obj.activities,
                    sha256_hash=obj.apk_hash,
                )
            if isinstance(obj, Path):
                return str(obj)
            if isinstance(obj, set):
                return list(obj)
            raise TypeError(
                f"Object of type {obj.__class__.__name__} is not JSON serializable by this function"
            )

        def pcap_analysis(self, app: AndroidApp) -> None:
            pcap_path = self.storage_helper.get_pcap_path(app)
            if pcap_path.is_file():
                self.stats.certificate_pinning_alerts = certificate_pinning. \
                    count_possible_certificate_pinning_alerts(pcap_path)

        def store_analysis_stats(self, app: AndroidApp, duration: float, do_pcap_analysis: bool = False) -> None:
            """Write analysis statistics to output directory.

            Detailed statistics are stored as json in app directory, simplified statistics are stored in
            output_directory as CSV-file.

            Args:
                app: AndroidApp the statistics belong to.
                duration: Seconds the analysis took to complete.
                do_pcap_analysis: Indicates whether a pcap analysis shall be performed during runtime. Not recommended.
            """
            self._logger.info(f"Storing analysis stats for app {app.app_package}, analysis took {duration} seconds")
            app_dir = self._get_app_dir(app)

            self.stats.app_metadata = app

            # Transform steps dict to list for reduced complexity
            temp = [
                self.stats.steps[step] for step in sorted(self.stats.steps.keys())
            ]
            self.stats.steps = temp

            # Assign arbitrary but unique state_id for better traceability in JSON
            state_id = 0
            for state in self.stats.unique_states:
                state.state_id = state_id
                state_id += 1

            for step in temp:
                if step.screenshot:
                    # Move screenshots to app_dir, name f"screenshot_{step.step_number:04d}.png"
                    new_screenshot_path = (
                            app_dir / f"screenshot_step_{step.step_number:04d}.png"
                    )
                    move(step.screenshot, new_screenshot_path)
                    step.screenshot = new_screenshot_path

            if do_pcap_analysis:
                self.pcap_analysis(app)

            with (app_dir / "analysis_stats.json").open(mode="a") as file:
                json.dump(self.stats, file, indent=3, default=self._json_encoding)

            # Store simplified stats in csv
            simple_stats = {
                "package_name": self.stats.app_metadata.app_package,
                "version": self.stats.app_metadata.version_string,
                "sha256": self.stats.app_metadata.apk_hash,
                "install_source": self.stats.app_metadata.install_source,
                "steps": len(self.stats.steps),
                "#gui_actions_seen": len(self.stats.actions_seen),
                "#unique_gui_actions_seen": len(self.stats.unique_actions_seen),
                "#gui_actions_executed": len(
                    [step for step in self.stats.steps if step.executed_action]
                ),
                "#gui_actions_executed_successfully": len(
                    [
                        step
                        for step in self.stats.steps
                        if step.executed_action and step.action_result
                    ]
                ),
                "#gui_actions_executed_unsuccessfully": len(
                    [
                        step
                        for step in self.stats.steps
                        if step.executed_action and not step.action_result
                    ]
                ),
                "#packages_visited": len(self.stats.packages_visited),
                "#all_activities_visited": len(self.stats.activities_visited),
                "#app_activities_extracted": len(self.stats.app_metadata.activities),
                "#app_activities_visited": len(
                    [
                        activity
                        for activity in self.stats.activities_visited
                        if activity.package.name == self.stats.app_metadata.app_package
                    ]
                ),
                "#unique_states": len(self.stats.unique_states),
                "refresh_count": self.stats.state_refresh_count,
                "back_count": len(
                    [
                        step
                        for step in self.stats.steps
                        if step.special_action and "BACK" in step.special_action
                    ]
                ),
                "return_to_app_count": len(
                    [
                        step
                        for step in self.stats.steps
                        if step.special_action and "RETURN" in step.special_action
                    ]
                ),
                "duration": duration,
                "certificate_pinning_alerts": self.stats.certificate_pinning_alerts
            }

            write_header = False
            header = [
                "package_name",
                "version",
                "sha256",
                "install_source",
                "steps",
                "#gui_actions_seen",
                "#unique_gui_actions_seen",
                "#gui_actions_executed",
                "#gui_actions_executed_successfully",
                "#gui_actions_executed_unsuccessfully",
                "#packages_visited",
                "#all_activities_visited",
                "#app_activities_extracted",
                "#app_activities_visited",
                "#unique_states",
                "refresh_count",
                "back_count",
                "return_to_app_count",
                "duration",
                "certificate_pinning_alerts"
            ]
            if not (self.root_directory / "simple_stats.csv").is_file():
                write_header = True
            with (self.root_directory / "simple_stats.csv").open(
                    mode="a", newline=""
            ) as file:
                if write_header:
                    csv.DictWriter(
                        file, fieldnames=header, delimiter=DELIMITER
                    ).writeheader()
                csv.DictWriter(file, fieldnames=header, delimiter=DELIMITER).writerow(
                    simple_stats
                )

            # Reset stats for next analysis
            self.stats = self.Stats()

        def add_to_step(
                self,
                step: int,
                screenshot: Optional[str] = None,
                state: Optional[State] = None,
                action: Optional[Action] = None,
                back_action: bool = False,
                return_action: bool = False,
        ) -> None:
            """Add information to step. Each datum can be added on its own.

            Args:
                step: Index of step. If not existing, step is created. Else data is added to existing step.
                screenshot: Path to screenshot. Defaults to None.
                state: State the step started with
                action: Action executed as part of the step.
                back_action: If True back action will be added to step.
                return_action: If True return action will be added to step.
            """
            if step not in self.stats.steps:
                self.stats.steps[step] = self.Step(step_number=step)
            step_obj = self.stats.steps[step]
            if state:
                step_obj.state_at_start = state
            if action:
                step_obj.executed_action = action
                step_obj.action_result = action.executed
            if back_action:
                step_obj.special_action = "BACK"
            if return_action:
                if step_obj.special_action:
                    step_obj.special_action += "; RETURN"
                else:
                    step_obj.special_action = "RETURN"
            if screenshot:
                step_obj.screenshot = screenshot

        def add_general_statistics(
                self,
                actions_seen: Optional[List[Action]] = None,
                unique_states: Optional[List[State]] = None,
                packages_visited: Optional[List[AndroidAppPackage]] = None,
                activities_visited: Optional[List[AndroidActivity]] = None,
                unique_actions_seen: Optional[List[Action]] = None,
        ) -> None:
            """Add general statistical information to current statistics. Each datum can be added on its own.

            Args:
                actions_seen: List of actions seen in the current step. The value is appended to the existing list.
                unique_states: List of unique states visited. Value replaces pre-existing-values.
                packages_visited: List of unique packages visited. Value replaces pre-existing-values.
                activities_visited: List of unique activities visited. Value replaces pre-existing-values.
                unique_actions_seen: List of unique actions seen. Value replaces pre-existing-values.
            """
            if actions_seen:
                self.stats.actions_seen += actions_seen
            if unique_states:
                self.stats.unique_states = unique_states
            if packages_visited:
                self.stats.packages_visited = packages_visited
            if activities_visited:
                self.stats.activities_visited = activities_visited
            if unique_actions_seen:
                self.stats.unique_actions_seen = unique_actions_seen

        def increase_state_refresh_count(self) -> None:
            """Increases state refresh count in current statistics by one.

            Call this before refreshing state.
            """
            self.stats.state_refresh_count += 1

    def _get_app_dir(self, android_app: AndroidApp) -> Path:
        """Creates app-specific results folder and returns path, if the directory already exists, it is simply returned

        Args:
            android_app: App the directory is created for

        Returns:
            Path to results folder
        """
        app_dir = self.root_directory / android_app.apk_hash
        app_dir.mkdir(parents=False, exist_ok=True)
        return app_dir

    def get_pcap_path(self, android_app: AndroidApp) -> Path:
        """Returns path to app-specific pcap output location.

        Args:
            android_app: App the pcap is to be created for

        Returns:
            Path to pcap output location
        """
        app_dir = self._get_app_dir(android_app)
        return app_dir / "analysis.pcap"

    def get_appium_log_path(self, android_app: AndroidApp) -> Path:
        """Returns path to app-specific appium output location.

        Args:
            android_app: App the appium log is to be created for

        Returns:
            Path to appium output location
        """
        app_dir = self._get_app_dir(android_app)
        return app_dir / "appium.log"

    def get_downloads_path(self) -> Path:
        return self.root_directory / "downloads"
