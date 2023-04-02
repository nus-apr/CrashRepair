import multiprocessing as mp
from app import emitter, oracle, definitions, values, generator, logger, extractor
from multiprocessing import TimeoutError
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
import time
import os
import sys
import collections

pool = None
result_list = []
def mute():
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

def collect_result(result):
    global result_list
    result_list.append(result)


def collect_result_timeout(result):
    global result_list, expected_count
    result_list.append(result)
    if len(result_list) == expected_count:
        pool.terminate()


def collect_result_one(result):
    global result_list, found_one
    result_list.append(result)
    if result[0] is True:
        found_one = True
        pool.terminate()


def abortable_worker(func, *args, **kwargs):
    default_value = kwargs.get('default', None)
    index = kwargs.get('index', None)
    p = ThreadPool(1)
    res = p.apply_async(func, args=args)
    try:
        out = res.get(values.DEFAULT_TIMEOUT_SAT)
        return out
    except TimeoutError:
        emitter.warning("\t[warning] timeout raised on a thread")
        return default_value, index


def generate_taint_sink_info(taint_symbolic, taint_memory_list, is_taint_influenced):
    """
        This function will analyse the taint values along the trace and identify taint sources
        for each location along the trace
               taint_symbolic: complete list of taint values for the trace
               returns a map for each source location their observed taint sources
     """
    global result_list
    taint_source_loc_map = collections.OrderedDict()
    taint_sink_loc_list = collections.OrderedDict()

    emitter.normal("\tgenerating taint map")
    logger.track_localization("generating taint map\n")
    emitter.highlight("\t\t[info] found " + str(len(taint_symbolic)) + " tainted locations")
    emitter.normal("\t\tstarting parallel computing")
    pool = mp.Pool(values.DEFAULT_CORE_LIMIT, initializer=mute)
    count = 0
    for taint_info in reversed(taint_symbolic.keys()):
        source_path, line_number, col_number, inst_addr = taint_info.split(":")
        if "/opt/zlib" in source_path or "/klee-uclibc/" in source_path:
            continue
        count = count + 1
        if count >= values.DEFAULT_MAX_TAINT_LOCATIONS:
            break

        taint_loc = ":".join([source_path, line_number, col_number])
        taint_expr_list = taint_symbolic[taint_info]
        logger.track_localization("Analysing Loc:" + taint_loc)
        if source_path not in taint_sink_loc_list:
            taint_sink_loc_list[source_path] = set()
        taint_sink_loc_list[source_path].add((line_number, col_number))
        if is_taint_influenced:
            # result_list.append(extractor.extract_taint_sources(taint_expr_list, taint_memory_list, taint_loc))
            pool.apply_async(extractor.extract_taint_sources,
                             args=(taint_expr_list, taint_memory_list, taint_loc),
                             callback=collect_result)
    pool.close()
    emitter.normal("\t\twaiting for thread completion")
    pool.join()
    for result in result_list:
        taint_loc, taint_source_list = result
        if taint_loc not in taint_source_loc_map:
            taint_source_loc_map[taint_loc] = list()
        if taint_source_list:
            taint_source_loc_map[taint_loc] = list(set(taint_source_loc_map[taint_loc] + taint_source_list))
        logger.track_localization("Source Location:" + taint_loc)
        logger.track_localization("Taint Sources:{}".format(taint_source_loc_map[taint_loc]))
    return taint_source_loc_map, taint_sink_loc_list
