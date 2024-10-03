#!/usr/bin/env python3

import logging
import time

class ExplorationBenchmark():
    """Allows for app state analysis before and after ExplorationStrategy steps."""
    def __init__(self, session):
        self.session = session
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        logger_handler = logging.StreamHandler()
        logger_handler.setFormatter(logging.Formatter('%(asctime)s: (%(levelname)s) %(name)s: %(message)s'))
        self.logger.addHandler(logger_handler)
    
    def before_step(self, step: int):
        pass

    def after_step(self, step: int):
        pass

class StepTimerExplorationBenchmark(ExplorationBenchmark):
    """Times how long each single step takes."""
    def __init__(self, session):
        super().__init__(session)
        self.step_start = 0

    def before_step(self, step: int):
        self.step_start = time.perf_counter()
    
    def after_step(self, step: int):
        self.logger.info('Step {} took {}s'.format(step, time.perf_counter() - self.step_start))
