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
    if os.path.exists(definitions.FILE_LAST_LOG):
        os.remove(definitions.FILE_LAST_LOG)
    if os.path.exists(definitions.FILE_ERROR_LOG):
        os.remove(definitions.FILE_ERROR_LOG)
    if os.path.exists(definitions.FILE_COMMAND_LOG):
        os.remove(definitions.FILE_COMMAND_LOG)
    if os.path.exists(definitions.FILE_LOCALIZE_LOG):
        os.remove(definitions.FILE_LOCALIZE_LOG)
    with open(definitions.FILE_LAST_LOG, 'w+') as last_log:
        last_log.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")
    with open(definitions.FILE_ERROR_LOG, 'w+') as error_log:
        error_log.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")
    with open(definitions.FILE_COMMAND_LOG, 'w+') as command_log:
        command_log.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")
    with open(definitions.FILE_LOCALIZE_LOG, 'w+') as command_log:
        command_log.write("[Start] " + values.TOOL_NAME + " started at " + str(datetime.datetime.now()) + "\n")

def store_log_file(log_file_path):
    if os.path.isfile(log_file_path):
        copyfile(log_file_path, definitions.DIRECTORY_LOG + "/" + log_file_path.split("/")[-1])

def store_logs():
    copyfile(definitions.FILE_MAIN_LOG, definitions.DIRECTORY_LOG + "/log-latest")
    store_log_file(definitions.FILE_COMMAND_LOG)
    store_log_file(definitions.FILE_ERROR_LOG)
    store_log_file(definitions.FILE_MAKE_LOG)
    store_log_file(definitions.FILE_CRASH_LOG)
    store_log_file(definitions.FILE_LOCALIZE_LOG)


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
    output("Sanitizer Run: " + str(time_duration[definitions.KEY_DURATION_SANITIZER]) + " minutes")
    output("Concolic Run: " + str(time_duration[definitions.KEY_DURATION_CONCOLIC]) + " minutes")
    output("Taint Run: " + str(time_duration[definitions.KEY_DURATION_TAINT]) + " minutes")
    output("Total Analysis: " + str(time_duration[definitions.KEY_DURATION_ANALYSIS]) + " minutes")
    output("Localization: " + str(time_duration[definitions.KEY_DURATION_LOCALIZATION]) + " minutes")

    if is_error:
        output(values.TOOL_NAME + " exited with an error after " + time_duration[
            definitions.KEY_DURATION_TOTAL] + " minutes")
    else:
        output(values.TOOL_NAME + " finished successfully after " + time_duration[
            definitions.KEY_DURATION_TOTAL] + " minutes")
    log("[END] " + values.TOOL_NAME + " ended at  " + str(datetime.datetime.now()) + "\n\n")


