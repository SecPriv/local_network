#!/usr/bin/env python3
from .exploration_session import ExplorationSession, iOSApp, iOSDevice
from .exploration_benchmarks import StepTimerExplorationBenchmark
from .exploration_strategies import ExplorationStrategy, NonRepeatingRandomButtonExplorationStrategy, iOSBFSExplorationStrategy, iOSDFSExplorationStrategy, iOSExplorationStrategy


class AppSimulator:

    def __init__(self, xcode_org_id: str, device_udid='auto', appium_host='localhost', appium_port=4723, device_ip = None):
        """
        device_udid can be 'auto' iff exactly one iOS device is connected via USB
        """
        self.xcode_org_id = xcode_org_id
        self.device_udid: str = device_udid
        self.appium_host: str = appium_host
        self.appium_port: int = appium_port
        self.device_ip:str = device_ip

    def start(self, bundle_id, steps, strategy):
        test_device = iOSDevice(udid=self.device_udid)
        test_app = iOSApp(bundle_id=bundle_id)

        command_executor = f'http://{self.appium_host}:{self.appium_port}/wd/hub'

        test_exploration_session = ExplorationSession(command_executor=command_executor,
                                                      xcode_org_id=self.xcode_org_id,
                                                      device=test_device,
                                                      app=test_app,
                                                      device_ip=self.device_ip)

        test_exploration_session.start()
        test_exploration_session.explore(explorer=strategy,
                                         benchmark=StepTimerExplorationBenchmark,
                                         steps=steps)
        test_exploration_session.stop()
