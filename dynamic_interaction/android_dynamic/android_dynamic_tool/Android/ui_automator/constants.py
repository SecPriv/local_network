from __future__ import annotations

from typing import List

from appium.webdriver.extensions.android import nativekey

from ..app import AndroidActivity, AndroidAppPackage


WIDGET_BUTTON_CLASSES = [
    "android.widget.Button",
    "android.widget.ImageButton",
]
LIKELY_CLICKABLE_CLASSES = ["android.widget.ImageView", "android.view.ViewGroup"]
WIDGET_INPUT_CLASSES = [
    "android.widget.EditText",
]
WIDGET_SKIP_CLASSES: List[str] = list()

ANDROID_CHROME_PACKAGE_NAME = "com.android.chrome"

ANDROID_PACKAGE_NAME = "android"
ANDROID_RESOLVER_ACTIVITY_NAME = "com.android.internal.app.ResolverActivity"
ANDROID_CHOOSER_ACTIVITY_NAME = "com.android.internal.app.ChooserActivity"
ANDROID_SYSTEM_DIALOG_ACTIVITIES = [
    AndroidActivity(
        name=ANDROID_RESOLVER_ACTIVITY_NAME,
        package=AndroidAppPackage(name=ANDROID_PACKAGE_NAME),
    ),
    AndroidActivity(
        name=ANDROID_CHOOSER_ACTIVITY_NAME,
        package=AndroidAppPackage(name=ANDROID_PACKAGE_NAME),
    ),
]

ANDROID_PLAY_STORE_MAIN_ACTIVITY = AndroidActivity(
    name=".AssetBrowserActivity", package=AndroidAppPackage(name="com.android.vending")
)
INSTALL_DURATION_IN_SECONDS = 40
WAIT_DURATION_IN_SECONDS = 20


ANDROID_HOME_KEY_CODE = nativekey.AndroidKey.HOME
ANDROID_ENTER_KEY_CODE = nativekey.AndroidKey.ENTER
