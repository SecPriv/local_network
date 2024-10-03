from __future__ import annotations

from typing import TYPE_CHECKING

from appium import webdriver

if TYPE_CHECKING:
    from exploration_benchmarks import ExplorationBenchmark
    from typing import Optional


class ExplorationSession:
    """Holds all data necessary for exploration, manages Appium session."""
    benchmark: ExplorationBenchmark
    appium_wd: Optional[webdriver.Remote]
