from http import server
import json
import logging
import threading
import subprocess

from ..app_analyzer import AppAnalyzer

# internal handler class, ExternalEventReceiver see below
class ExternalEventHandler(server.BaseHTTPRequestHandler):
    analyzer: any

    def do_GET(self):
        if self.path == '/stop':
            threading.Thread(
                target=lambda x: self.server.shutdown(), args=(1,), daemon=True).start()

        self.send_response(200)
        self.end_headers()

    def reply_status(self, status: int):
        self.send_response(status)
        self.end_headers()

    def do_POST(self):
        if not self.path.startswith('/event/'):
            self.reply_status(404)
            return

        event_name = self.path[len('/event/'):]

        if len(event_name) == 0:
            logging.warning('event with no name received, ignoring')
            self.reply_status(404)
            return

        try:
            content_length = int(self.headers['Content-Length'])

            content_json = self.rfile.read(content_length).decode('utf-8')
            content_dict = json.loads(content_json)
        except Exception as ex:
            logging.exception('could not parse request (ignoring)')

            self.reply_status(400)
            return

        logging.debug('received json:', content_dict)

        if self.variables.analyzer != None:
            self.variables.analyzer.handle_external_event(
                event_name, content_dict)
        else:
            logging.warning(
                'WARNING: external event handler has received an event but no analyzer is set!')

        self.reply_status(200)


class HTTPEventHandlerSharedContainer:
    analyzer: AppAnalyzer
    pass


class ExternalEventReceiver(threading.Thread):
    """
    Listens on the local network for http events, so that external analysis tools can simply add their events to the main analysis log.
    To add an event, call POST /events/<event_name> with a json body.
    """

    def __init__(self, port=8042, address=''):
        self._srv: server.HTTPServer = None

        self.port: int = port
        self.address: str = address
        self.eventHandlerVariables = HTTPEventHandlerSharedContainer()
        super().__init__()

    def get_pid(self, port):
        try:
            # Run the lsof command and capture its output
            result = subprocess.run(['lsof', '-t', f'-i:{port}'], capture_output=True, text=True, check=True)

            # Extract the process ID (PID) from the output
            pid = result.stdout.strip()

            return pid
        except subprocess.CalledProcessError:
            # Handle the case where the lsof command fails (e.g., if the port is not in use)
            print(f"No process found using port {port}")
            return None


    def start_notifying(self, analyzer: AppAnalyzer):
        self.eventHandlerVariables.analyzer = analyzer

    def stop_notifying(self):
        self.eventHandlerVariables.analyzer = None

    def run(self) -> None:
        self._run_server(self.port, self.address)

    def _run_server(self, port, address=''):
        logging.info(f'starting to serve on {address}:{port}...')
        pid = self.get_pid(port)

        if pid != None and len(pid) > 0:
            subprocess.Popen(["kill", f"{pid}"]) # kill mitm
        server_address = (address, port)

        ExternalEventHandler.variables = self.eventHandlerVariables
        self._srv = server.ThreadingHTTPServer(
            server_address, ExternalEventHandler)


        self._srv.serve_forever()

        logging.info('shuttung down server')

    def stop(self):
        if self._srv != None:
            self._srv.shutdown()
