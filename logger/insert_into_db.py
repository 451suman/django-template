from queue import Queue
import signal
from sqlite3 import OperationalError
from threading import Event, Thread
import time

from django.conf import settings

from logger.models.apilog_model import ApiLogModel


class InsertIntoDatabase(Thread):
    def __init__(self):
        super().__init__()

        # Needed to stop thread gracefully
        self._stop_event = Event()

        self.API_LOGGER_DEFAULT_DATABASE = "default"
        if hasattr(settings, "API_LOGGER_DEFAULT_DATABASE"):
            self.API_LOGGER_DEFAULT_DATABASE = settings.API_LOGGER_DEFAULT_DATABASE

        self.LOGGER_MAX_QUEUE_SIZE = 50
        if hasattr(settings, "LOGGER_MAX_QUEUE_SIZE"):
            self.LOGGER_MAX_QUEUE_SIZE = settings.LOGGER_MAX_QUEUE_SIZE

        if self.LOGGER_MAX_QUEUE_SIZE < 1:
            raise Exception("""

            LOGGER QUEUE SIZE Exception
            Max queue size(LOGGER_MAX_QUEUE_SIZE) cannot be less than 1
            """)

        self.LOGGER_WRITE_INTERVAL = 5  # Interval to write queued logs into DB
        if hasattr(settings, "LOGGER_WRITE_INTERVAL"):
            self.LOGGER_WRITE_INTERVAL = settings.LOGGER_WRITE_INTERVAL

            if self.LOGGER_WRITE_INTERVAL < 1:
                raise Exception("""
                API LOGGER WRITE INTERVAL Exception
                Value of LOGGER_WRITE_INTERVAL should be greater than 1
                """)

            self._queue = Queue(maxsize=self.LOGGER_MAX_QUEUE_SIZE)
            signal.signal(signal.SIGINT, self._clean_exit)
            signal.signal(signal.SIGTERM, self._clean_exit)

    def run(self) -> None:
        """Entry point, start queue processing loop"""
        self.start_queue_process()

    def _insert_into_database(self, bulk_item):
        try:
            ApiLogModel.objects.using(self.API_LOGGER_DEFAULT_DATABASE).bulk_create(
                bulk_item
            )
        except OperationalError:
            raise Exception(
                """
                API LOGGER EXCEPTION
                Model doesn't exist
                Forgot to migrate?
                """
            )

    def put_log_data(self, data):
        self._queue.put(ApiLogModel(**data))

        if self._queue.qsize() >= self.LOGGER_MAX_QUEUE_SIZE:
            self._start_bulk_insertion()

    def start_queue_process(self):
        while not self._stop_event.set():
            time.sleep(self.LOGGER_WRITE_INTERVAL)
            self._start_bulk_insertion()

    def _start_bulk_insertion(self):
        bulk_item = []
        while not self._queue.empty():
            bulk_item.append(self._queue.get())

        if bulk_item:
            self._insert_into_database(bulk_item)

    def _clean_exit(self, signum, frame):
        """
        Signal handler called when process is exiting
        Sets stop event and flushes any logs in queue into database

        Args:
            signum : Signal number recieved
            frame : current stack frame (could be used in future)
        """

        self._stop_event.set()
        self._start_bulk_insertion()
        exit(0)
