from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
from pathlib import Path
import os
import json
import ndjson


class AnalysisEventLogger(ABC):
    @abstractmethod
    def log(self, access_type: str, event_name: str, info: dict):
        """
        Logs the given info, along with the event name, access type and current timestamp.
        access_type is the general type of the event, e.g. 'network'
        event_name is the concrete event, e.g. 'url_request'
        the info dict may contain additional info about the event
        If the given info dictionary contains the fields event_name or timestamp, it will be overriden in the log output
        """

        pass


class NdJSONLogger(AnalysisEventLogger):
    def __init__(self, out_folder_path, filename_prefix) -> None:
        path = Path(out_folder_path)
        path.mkdir(parents=True, exist_ok=True)

        self.analysis_file_name = out_folder_path + '/' + \
            filename_prefix + "_log.ndjson"

        self.file = open(self.analysis_file_name, 'w+')
        logging.info(f"analysis log file opened: {self.analysis_file_name}")

        self.writer = ndjson.writer(self.file)  # , ensure_ascii=False)

    def log(self, access_type: str, event_name: str, info: dict):
        info["access_type"] = access_type
        info["event_name"] = event_name
        info["timestamp"] = datetime.now(tz=timezone.utc).isoformat()

        self.writer.writerow(info)
        self.file.flush()

    def close(self):
        self.file.close()

        self.file = None
        self.writer = None


class AnalysisReportWriter:
    def __init__(self, out_folder_path, filename_prefix) -> None:
        if not os.path.isdir(out_folder_path):
            logging.info(f"creating output directory '{out_folder_path}'")
            os.mkdir(out_folder_path)

        self.analysis_file_name = out_folder_path + '/' + \
            filename_prefix + "_analysis.json"

        # prepare analysis output structure
        self.analysis_output = {
            "analysisInfo": {},
            "appInfo": {},
            "accessTypes": {},
            "logVersion": 1.0
        }

    def update_report(self, title: str, report: dict, flush: bool = True):
        self.analysis_output["accessTypes"][title] = report
        if flush:
            self.flush()

    def update_app_info(self, key: str, info: any):
        self.analysis_output["appInfo"][key] = info
        self.flush()

    def update_analysis_info(self, key: str, info: any):
        self.analysis_output["analysisInfo"][key] = info
        self.flush()

    def flush(self):
        f = open(self.analysis_file_name, 'w')
        try:
            json.dump(self.analysis_output, f, indent=2)
            logging.info(
                f"analysis report updated at {self.analysis_file_name}")
        except:
            logging.warning(
                f'failed to write out analysis file at {self.analysis_file_name}')
        finally:
            f.close()
