import os
import time
import traceback
import signal
import multiprocessing as mp

import app.configuration
import app.utilities
from app import emitter, logger, definitions, values,  \
    configuration, analyzer, parallel, localizer

start_time = 0
time_info = {
    definitions.KEY_DURATION_INITIALIZATION: '0',
    definitions.KEY_DURATION_BUILD: '0',
    definitions.KEY_DURATION_BOOTSTRAP: '0',
    definitions.KEY_DURATION_SANITIZER: '0',
    definitions.KEY_DURATION_CONCOLIC: '0',
    definitions.KEY_DURATION_TAINT: '0',
    definitions.KEY_DURATION_LOCALIZATION: '0',
    definitions.KEY_DURATION_ANALYSIS: '0',
    definitions.KEY_DURATION_REPAIR: '0',
    definitions.KEY_DURATION_TOTAL: '0'
    }

stop_event = mp.Event()


def create_directories():
    if not os.path.isdir(definitions.DIRECTORY_LOG_BASE):
        os.makedirs(definitions.DIRECTORY_LOG_BASE)

    if not os.path.isdir(definitions.DIRECTORY_OUTPUT_BASE):
        os.makedirs(definitions.DIRECTORY_OUTPUT_BASE)

    if not os.path.isdir(definitions.DIRECTORY_BACKUP):
        os.makedirs(definitions.DIRECTORY_BACKUP)

    if not os.path.isdir(definitions.DIRECTORY_TMP):
        os.makedirs(definitions.DIRECTORY_TMP)


def timeout_handler(signum, frame):
    emitter.error("TIMEOUT Exception")
    raise Exception("end of time")


def shutdown(signum, frame):
    global stop_event
    emitter.warning("Exiting due to Terminate Signal")
    stop_event.set()
    raise SystemExit


def bootstrap(arg_list):
    emitter.header("Starting " + values.TOOL_NAME + " (C Crash Repair) ")
    emitter.sub_title("Loading Configurations")
    configuration.read_conf(arg_list)
    configuration.read_conf_file()
    configuration.update_configuration()

    configuration.collect_test_list()
    configuration.collect_seed_list()
    # configuration.collect_var_mapping()
    configuration.print_configuration()
    values.CONF_ARG_PASS = True
    app.utilities.check_budget(values.DEFAULT_TIME_DURATION)


def run(arg_list):
    global start_time, time_info
    create_directories()
    logger.create()
    start_time = time.time()

    time_check = time.time()
    bootstrap(arg_list)
    duration = format((time.time() - time_check) / 60, '.3f')
    time_info[definitions.KEY_DURATION_BOOTSTRAP] = str(duration)

    time_check = time.time()
    input_byte_list, taint_symbolic, cfc_info, taint_concrete = analyzer.analyze()

    duration = format((time.time() - time_check) / 60, '.3f')
    time_info[definitions.KEY_DURATION_ANALYSIS] = str(duration)
    time_info[definitions.KEY_DURATION_CONCOLIC] = values.TIME_CONCOLIC_ANALYSIS
    time_info[definitions.KEY_DURATION_SANITIZER] = values.TIME_SANITIZER_RUN
    time_info[definitions.KEY_DURATION_TAINT] = values.TIME_TAINT_ANALYSIS


    time_check = time.time()
    localizer.fix_localization(input_byte_list, taint_symbolic, cfc_info, taint_concrete)
    duration = format((time.time() - time_check) / 60, '.3f')
    time_info[definitions.KEY_DURATION_LOCALIZATION] = str(duration)


    # time_check = time.time()
    # repair.run(values.CONF_PATH_PROJECT, values.CONF_PATH_PROGRAM)
    # duration = format(((time.time() - time_check) / 60 - float(values.TIME_TO_GENERATE)), '.3f')
    # time_info[definitions.KEY_DURATION_REPAIR] = str(duration)


def main():
    import sys
    is_error = False
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        run(sys.argv[1:])
    except SystemExit as e:
        total_duration = format((time.time() - start_time) / 60, '.3f')
        time_info[definitions.KEY_DURATION_TOTAL] = str(total_duration)
        emitter.end(time_info, is_error)
        logger.end(time_info, is_error)
        logger.store_logs()
        parallel.pool.terminate()
        parallel.pool.join()
        # os.system("ps -aux | grep 'cpr' | awk '{print $2}' | xargs kill -9")
    except KeyboardInterrupt as e:
        total_duration = format((time.time() - start_time) / 60, '.3f')
        time_info[definitions.KEY_DURATION_TOTAL] = str(total_duration)
        emitter.end(time_info, is_error)
        logger.end(time_info, is_error)
        logger.store_logs()
    except Exception as e:
        is_error = True
        emitter.error("Runtime Error")
        emitter.error(str(e))
        logger.error(traceback.format_exc())
    finally:
        # Final running time and exit message
        # os.system("ps -aux | grep 'python' | awk '{print $2}' | xargs kill -9")
        total_duration = format((time.time() - start_time) / 60, '.3f')
        time_info[definitions.KEY_DURATION_TOTAL] = str(total_duration)
        emitter.end(time_info, is_error)
        logger.end(time_info, is_error)
        logger.store_logs()
        if is_error:
            exit(1)
        exit(0)
