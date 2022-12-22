# -*- coding: utf-8 -*-

import time
import datetime
import os
from app import definitions, values
from shutil import copyfile


def create():
    log_file_name = "log-" + str(time.time())
    log_file_path = definitions.DIRECTORY_LOG_BASE + "/" + log_file_name
    definitions.FILE_MAIN_LOG = log_file_path
    with open(definitions.FILE_MAIN_LOG, 'w+') as log_file:
        log_file.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")

    for log_file in [definitions.FILE_LAST_LOG,definitions.FILE_ERROR_LOG, definitions.FILE_COMMAND_LOG,
                     definitions.FILE_LOCALIZE_LOG, definitions.FILE_EXCEPTION_LOG]:
        if os.path.exists(log_file):
            os.remove(log_file)
        with open(log_file, 'w+') as last_log:
            last_log.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")


def store_log_file(log_file_path):
    if os.path.isfile(log_file_path):
        copyfile(log_file_path, definitions.DIRECTORY_LOG + "/" + log_file_path.split("/")[-1])

def store_logs():
    copyfile(definitions.FILE_MAIN_LOG, definitions.DIRECTORY_LOG + "/log-latest")
    for log_file in [definitions.FILE_COMMAND_LOG, definitions.FILE_ERROR_LOG,
                     definitions.FILE_MAKE_LOG, definitions.FILE_EXCEPTION_LOG,
                     definitions.FILE_CRASH_LOG, definitions.FILE_LOCALIZE_LOG]:
        store_log_file(log_file)


def log(log_message):
    log_message = "[" + str(time.asctime()) + "]" + log_message
    if "COMMAND" in log_message:
        with open(definitions.FILE_COMMAND_LOG, 'a') as log_file:
            log_file.write(log_message)
    with open(definitions.FILE_MAIN_LOG, 'a') as log_file:
        log_file.write(log_message)
    with open(definitions.FILE_LAST_LOG, 'a') as log_file:
        log_file.write(log_message)


def information(message):
    message = str(message).strip()
    message = "[INFO]: " + str(message) + "\n"
    log(message)


def trace(function_name, arguments):
    message = "[TRACE]: " + function_name + ": " + str(arguments.keys()) + "\n"
    log(message)

def track_localization(log_message):
    log_output = "[{}]: {}\n".format(time.asctime(), log_message)
    with open(definitions.FILE_LOCALIZE_LOG, 'a') as log_file:
        log_file.write(log_output)

def exception(exception, data):
    template = "An exception of type {0} occurred. Arguments:\n{1!r}"
    message = template.format(type(exception).__name__, exception.args)
    log_output = "[{}]: {}\n".format(time.asctime(), message)
    with open(definitions.FILE_EXCEPTION_LOG, 'a') as log_file:
        log_file.write(log_output)
        log_file.write(data)

def command(message):
    message = str(message).strip().replace("[command]", "")
    message = "[COMMAND]: " + str(message) + "\n"
    log(message)


def data(message, data=None, is_patch=False):
    if values.DEBUG or is_patch:
        message = str(message).strip()
        message = "[DATA]: " + str(message) + "\n"
        log(message)
        if data:
            data = "[DATA]: " + str(data) + "\n"
            log(data)


def debug(message):
    message = str(message).strip()
    message = "[DEBUG]: " + str(message) + "\n"
    log(message)


def error(message):
    with open(definitions.FILE_ERROR_LOG, 'a') as last_log:
        last_log.write(str(message) + "\n")
    message = str(message).strip().lower().replace("[error]", "")
    message = "[ERROR]: " + str(message) + "\n"
    log(message)


def note(message):
    message = str(message).strip().lower().replace("[note]", "")
    message = "[NOTE]: " + str(message) + "\n"
    log(message)


def configuration(message):
    message = str(message).strip().lower().replace("[config]", "")
    message = "[CONFIGURATION]: " + str(message) + "\n"
    log(message)


def output(message):
    message = str(message).strip()
    message = "[LOG]: " + message
    log(message + "\n")


def warning(message):
    message = str(message).strip().lower().replace("[warning]", "")
    message = "[WARNING]: " + str(message) + "\n"
    log(message)


def end(time_duration, is_error=False):
    output("\nTime duration\n----------------------\n\n")
    output("Startup: " + str(time_duration[definitions.KEY_DURATION_BOOTSTRAP]) + " minutes")
    output("Build: " + str(time_duration[definitions.KEY_DURATION_BUILD]) + " minutes")
    output("Concrete Analysis: " + str(time_duration[definitions.KEY_DURATION_CONCRETE]) + " minutes")
    output("Concolic Analysis: " + str(time_duration[definitions.KEY_DURATION_CONCOLIC]) + " minutes")
    output("Total Analysis: " + str(time_duration[definitions.KEY_DURATION_ANALYSIS]) + " minutes")
    output("Localization: " + str(time_duration[definitions.KEY_DURATION_LOCALIZATION]) + " minutes")

    if is_error:
        output(values.TOOL_NAME + " exited with an error after " + time_duration[
            definitions.KEY_DURATION_TOTAL] + " minutes")
    else:
        output(values.TOOL_NAME + " finished successfully after " + time_duration[
            definitions.KEY_DURATION_TOTAL] + " minutes")
    log("[END] " + values.TOOL_NAME + " ended at  " + str(datetime.datetime.now()) + "\n\n")


