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


def generate_loc_to_bytes(taint_symbolic, is_taint_influenced):
    """
        This function will analyse the taint values along the trace and identify taint sources
        for each location along the trace
               taint_symbolic: complete list of taint values for the trace
               returns a map for each source location their observed taint sources
     """
    global result_list
    loc_to_byte_map = collections.OrderedDict()
    source_mapping = collections.OrderedDict()

    emitter.normal("\tgenerating taint map")
    logger.track_localization("generating taint map\n")
    emitter.highlight("\t\t[info] found " + str(len(taint_symbolic)) + " tainted locations")
    emitter.normal("\t\tstarting parallel computing")
    pool = mp.Pool(mp.cpu_count(), initializer=mute)
    count = 0
    for taint_info in taint_symbolic:
        count = count + 1
        if count >= values.DEFAULT_MAX_TAINT_LOCATIONS:
            break
        source_path, line_number, col_number, inst_addr = taint_info.split(":")
        taint_loc = ":".join([source_path, line_number, col_number])
        taint_expr_list = taint_symbolic[taint_info]
        logger.track_localization("TAINT LOC:" + taint_loc)
        if source_path not in source_mapping:
            source_mapping[source_path] = set()
        source_mapping[source_path].add((line_number, col_number))
        if is_taint_influenced:
            result_list.append(generator.generate_taint_sources(taint_expr_list, taint_loc))
            # pool.apply_async(generator.generate_taint_sources,
            #                  args=(taint_expr_list, taint_loc),
            #                  callback=collect_result)
    pool.close()
    emitter.normal("\t\twaiting for thread completion")
    pool.join()
    for result in result_list:
        taint_loc, taint_source_list = result
        loc_to_byte_map[taint_loc] = list(set(taint_source_list))
        logger.track_localization("TAINT SOURCES:{}".format(loc_to_byte_map[taint_loc]))
    return loc_to_byte_map, source_mapping
