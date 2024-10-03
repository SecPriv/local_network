from __future__ import annotations

import logging
import time

from .exploration_session import ExplorationSession
from ..helper.constants import LOGGER_BASE_NAME

logger: logging.Logger = logging.getLogger(LOGGER_BASE_NAME + ".exploration-benchmarks")


class ExplorationBenchmark:
    """Allows for app state analysis before and after ExplorationStrategy steps."""

    def __init__(self, session: ExplorationSession):
        self.session = session

    def before_step(self, step: int) -> None:
        """Stores state before step.

        Args:
            step: Step number
        """
        pass

    def after_step(self, step: int) -> None:
        """Checks state after step and evaluates change.

        Args:
            step: Step number
        """
        pass


class StepTimerExplorationBenchmark(ExplorationBenchmark):
    """Times how long each single step takes."""
    step_start: float

    def __init__(self, session: ExplorationSession):
        super().__init__(session)
        self.step_start = 0

    def before_step(self, step: int) -> None:
        """Stores time before step.

        Args:
            step: Step number
        """
        self.step_start = time.perf_counter()

    def after_step(self, step: int) -> None:
        """Checks time after step and logs difference.

        Args:
            step: Step number
        """
        logger.info(
            "Step {} took {}s".format(step, time.perf_counter() - self.step_start)
        )
