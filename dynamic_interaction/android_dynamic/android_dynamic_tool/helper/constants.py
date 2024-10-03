from __future__ import annotations

from logging import Formatter
import os
from pathlib import Path
from tempfile import mkdtemp

LOGGER_BASE_NAME = "cross-platform-pps"

# EMULATOR CONSTANTS #
# This has to be changed in order to work with a different system
AVD_HOME_DIRECTORY = Path(r"~/.android/avd/").expanduser()

# Set emulator path here, if the default values inferred from ANDROID_SDK_ROOT are wrong or ANDROID_SDK_ROOT is not set
PATH_TO_EMULATOR = ""
PATH_TO_ADB = ""

if "ANDROID_SDK_ROOT" in os.environ:
    if not PATH_TO_EMULATOR:
        PATH_TO_EMULATOR = str((Path(os.environ["ANDROID_SDK_ROOT"]) / "emulator" / "emulator").absolute())
    if not PATH_TO_ADB:
        PATH_TO_ADB = str((Path(os.environ["ANDROID_SDK_ROOT"]) / "platform-tools" / "adb").absolute())

if not Path(PATH_TO_ADB).is_file():
    raise FileNotFoundError(PATH_TO_ADB)

if not Path(PATH_TO_EMULATOR).is_file():
    raise FileNotFoundError(PATH_TO_EMULATOR)

EMULATOR_SUCCESS_STRING = "emulator: INFO: boot completed"

EMULATOR_ANDROID_DEFAULT_LAUNCHER_PACKAGE_NAMES = {
    "10": "com.google.android.apps.nexuslauncher",  # Without PlayStore: com.android.launcher3
    "11": "com.google.android.apps.nexuslauncher"
}

LOG_FORMATTER = Formatter("%(asctime)s: (%(levelname)s) %(name)s: %(message)s")

TMP_ROOT = mkdtemp(prefix=LOGGER_BASE_NAME+"-")
