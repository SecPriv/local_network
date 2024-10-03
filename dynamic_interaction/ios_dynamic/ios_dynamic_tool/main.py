from argparse import ArgumentParser
from pathlib import Path
from pipeline import AnalysisPipeline
import logging
from datetime import datetime, timezone
import time
import frida


def configure_global_logging(out_folder, enable_debugging: bool):
    # create output folder if it does not exist
    Path(out_folder).mkdir(parents=True, exist_ok=True)

    logging.Formatter.converter = (
        time.gmtime
    )  # log in UTC (=GMT), in accordance to the used filenames
    logging_filename_prefix = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    logging_filename = f"{out_folder}/{logging_filename_prefix}_log.log"
    logging.basicConfig(
        level=logging.INFO if not enable_debugging else logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(logging_filename), logging.StreamHandler()],
    )


def start_analysis(
    analysis_output_folder: str,
    bundle_id: str,
    xcode_org_id: str,
    device_udid: str = "auto",
    simulation_steps: int = 10,
    appium_host: str = "localhost",
    appium_port: int = 4723,
    debug: bool = False,
    no_frida: bool = False,
    event_receiver_port: int = 8042,
    device_ip: str = None
):
    configure_global_logging(analysis_output_folder, debug)

    pipeline = AnalysisPipeline(
        bundle_id=bundle_id,
        xcode_org_id=xcode_org_id,
        device_udid=device_udid,
        appium_host=appium_host,
        appium_port=appium_port,
        analysis_output_folder=analysis_output_folder,
        event_receiver_port=event_receiver_port,
        device_ip = device_ip
    )

    try:
        pipeline.run_analysis(
            simulation_steps=simulation_steps, no_frida = no_frida
        )
    except frida.NotSupportedError as ex:
        handle_failed_app(
            bundle_id,
            f"failed to attach to app - is jailbreak active and frida installed on iPhone?, exception: {ex}",
        )
    except KeyboardInterrupt:
        handle_failed_app(
            bundle_id,
            f"keyboard interrupt, analysis aborted, further apps skipped.",
        )
        logging.info("received keyboard interrupt, skipping remaining apps")
    except Exception as ex:
        import traceback
        print(traceback.format_exc())
        handle_failed_app(bundle_id, f"running analysis failed: {ex}")

    handle_success_app(bundle_id)
    pipeline.close()


def main():
    args_parser = ArgumentParser(
        description="""
            Runs analysis pipeline. By default, only the analysis is executed.
        """
    )
    args_parser.add_argument(
        "-u",
        "--udid",
        help="The UDID of the target iOS device. 'auto' suffices if only one device is connected. (default: 'auto')",
        metavar="DEVICE_UDID",
        default="auto",
    )
    args_parser.add_argument(
        "-s",
        "--steps",
        type=int,
        help="Number of UI simulation steps (i.e. number of simulated taps) (default: 10)",
        metavar="COUNT",
        default=25,
    )
    args_parser.add_argument(
        "-i",
        "--bundle-id",
        help="The bundle id of the app to analyse.",
        type=str,
        required=True,
    )
    args_parser.add_argument(
        "-o",
        "--output-dir",
        help="The output folder for the produced analysis files. (default: out)",
        default="./out",
    )
    args_parser.add_argument(
        "-x",
        "--xcode-org-id",
        help="XCode Org ID, needed for Appium on a real device, see https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/",
        required=True,
    )
    args_parser.add_argument(
        "--appium_host",
        help="The host or IP address of the appium server (default: localhost)",
        metavar="HOST_OR_IP",
        default="localhost",
    )
    args_parser.add_argument(
        "--appium_port",
        help="The port of the appium server (default: 4723)",
        type=int,
        metavar="PORT",
        default=4723,
    )
    args_parser.add_argument(
        "--debug", help="Sets log level to debug.", action="store_true"
    )
    args_parser.add_argument(
        "-nf", "--no-frida", help="Execute analysis without frida.", action="store_true"
    )
    args_parser.add_argument(
        "--event-receiver-port",
        help="The port of the event receiver server (default: 8042)",
        type=int,
        metavar="PORT",
        default=8042,
    )

    args_parser.add_argument(
        "--device-ip",
        help="The host or IP address of the iphone",
        metavar="HOST_OR_IP",
        default="localhost",
    )

    args = args_parser.parse_args()
    analysis_output_folder = args.output_dir
    bundle_id = args.bundle_id
    device_udid = args.udid
    simulation_steps = args.steps
    appium_host = args.appium_host
    appium_port = args.appium_port
    xcode_org_id = args.xcode_org_id
    debug = args.debug
    no_frida = args.no_frida
    event_receiver_port = args.event_receiver_port
    device_ip =args.device_ip

    start_analysis(
        analysis_output_folder=analysis_output_folder,
        bundle_id=bundle_id,
        device_udid=device_udid,
        simulation_steps=simulation_steps,
        appium_host=appium_host,
        appium_port=appium_port,
        xcode_org_id=xcode_org_id,
        debug=debug,
        no_frida = no_frida,
        event_receiver_port=event_receiver_port,
        device_ip = device_ip
    )


def handle_failed_app(app_store_id, reason):
    logging.error(f"task failed for app {app_store_id}: {reason}")
    

def handle_success_app(app_store_id):
    logging.info(f"tasks succeeded for app {app_store_id}")
    

def run_analysis(pipeline, app_store_id, steps) -> str:
    """Returns bundle id"""
    bundle_id = pipeline.run_analysis(app_store_id, steps)
    return bundle_id


if __name__ == "__main__":
    main()
