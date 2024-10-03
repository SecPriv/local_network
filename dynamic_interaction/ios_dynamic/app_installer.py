import hashlib
import os
import subprocess
import re


class AppInstaller():
    """
    This class manages (un-)installation and hashing of the app to analyze.
    """

    ipa_path = None
    udid = None
    bundle_id = None
    app_hash = None

    ideviceinstaller_install_process = None
    ideviceinstaller_uninstall_process = None

    def __init__(self, ipa_path: str, udid: str):
        self.ipa_path = os.path.abspath(ipa_path)
        self.udid = udid

    def _get_udid(self) -> str:
        """
        Gets the id of the connected USB device. If not already set, it calls 'idevice_id' and uses the FIRST connected device.
        """
        if self.udid is None:
            # gets device id. format of output is '<device-id> (USB)', hence we remove the (USB) part
            self.udid = subprocess.check_output('idevice_id').decode("utf-8").split(' ')[0]
        return self.udid

    def _calculate_sha256(self, file_path:str) -> str:
        """
        Calculates the hash (sha256) of a given file in chunks to better handle large files.
        See: https://www.debugpointer.com/python/create-sha256-hash-of-a-file-in-python
        """
        hash_sha256 = hashlib.sha256()
        chunk_size = 4096
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def get_app_hash(self) -> str:
        if self.app_hash is not None:
            return self.app_hash
        else:
            return self._calculate_sha256(self.ipa_path)

    def install(self) -> None:
        """
        Installs the .ipa to the phone. Apple ID on the phone must be the same when app was downloaded, otherwise the app will not open.
        """
        ideviceinstaller_install_process = subprocess.Popen(['ideviceinstaller', '--udid', self._get_udid(), '--install', self.ipa_path])
        ideviceinstaller_install_process.wait()

        # check exitcode to determine whether the download was successful
        return_code = ideviceinstaller_install_process.returncode
        if return_code > 0:
            raise RuntimeError("Could not install ipa.")

        ideviceinstaller_install_process = None

    def get_installed_apps(self) -> [str]:
        """
        Uninstalls the app from the phone using ideviceinstaller.
        """
        output = subprocess.check_output(['ideviceinstaller', '--udid', self._get_udid(), '--list-apps', '-o', 'list_user']).decode("utf-8")
        result = []
        for line in output.splitlines():
            if line.startswith("CFBundleIdentifier, "):
                continue

            result.append(line.split(",")[0])

        return result






    def uninstall(self, bundle_id) -> None:
        """
        Uninstalls the app from the phone using ideviceinstaller.
        """
        ideviceinstaller_uninstall_process = subprocess.Popen(['ideviceinstaller', '--udid', self._get_udid(), '--uninstall', bundle_id])
        ideviceinstaller_uninstall_process.wait()

       # check exitcode to determine whether the download was successful
        return_code = ideviceinstaller_uninstall_process.returncode
        if return_code > 0:
            raise RuntimeError("Could not uninstall ipa.")

        ideviceinstaller_uninstall_process = None
