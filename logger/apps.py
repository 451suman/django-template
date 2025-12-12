import os
from django.apps import AppConfig
from logger.utils import db_log_enabled

LOGGER_THREAD = None


class LoggerConfig(AppConfig):
    name = "logger"
    verbose_name = "API Logger"

    def ready(self):
        global LOGGER_THREAD

        should_start_thread = (
            os.environ.get("RUN_LOGGER") == "true"
            or os.environ.get("RUN_LOGGER") is None
        )

        if should_start_thread:
            if db_log_enabled():
                from logger.insert_into_db import InsertIntoDatabase
                import threading

                LOG_THREAD_NAME = "insert_into_db"

                # Check for thread to avoid multiple threads
                already_exists = False
                for t in threading.enumerate():
                    if t.name == LOG_THREAD_NAME:
                        already_exists = True
                        break

                if not already_exists:
                    t = InsertIntoDatabase()  # subclass of threading.Thread
                    t.daemon = True  # Making it daemon so it closes with main thread and doesn't run indefinetly (really bad issue)
                    t.name = LOG_THREAD_NAME  # Name for easy identification in case needed to kill ;)
                    t.start()  # Bg process for insertion of log
                    LOGGER_THREAD = t
