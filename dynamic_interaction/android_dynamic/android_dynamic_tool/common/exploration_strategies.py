from __future__ import annotations

import logging

from .exploration_session import ExplorationSession
from ..helper.storage_helper import StorageHelper
from ..helper.constants import LOGGER_BASE_NAME

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".exploration-strategies")


class ExplorationStrategy:
    """Handles app state analysis and decides on steps to take next."""

    def __init__(self, session: ExplorationSession):
        """Initializes with existing ExplorationSession."""
        self.session = session

    def explore(self, results_helper: StorageHelper.AnalysisResultsHelper, steps: int = 1000) -> None:
        """Starts automatic exploration.

        Args:
            results_helper: Helper used to store intermediate results/steps.
            steps: The number of steps to take to explore the app. Defaults to 1000.
        """
        logger.info("Starting exploration for {} steps".format(steps))
        for i in range(1, steps + 1):
            self.session.benchmark.before_step(step=i)
            self.execute_next_step(step=i)
            self.session.benchmark.after_step(step=i)

    def execute_next_step(self, step: int) -> None:
        raise NotImplementedError
