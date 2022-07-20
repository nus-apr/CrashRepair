import multiprocessing as mp
from app import emitter, oracle, definitions, values, generator
from multiprocessing import TimeoutError
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
import time
import os
import sys

pool = None
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


def generate_special_paths(ppc_list, arg_list, poc_path, bin_path):
    global pool, result_list, expected_count
    result_list = []
    path_list = []
    filtered_list = []
    lock = None
    count = 0
    expected_count = len(ppc_list)
    ppc_list.reverse()
    if values.DEFAULT_OPERATION_MODE in ["sequential", "semi-parallel"]:
        for con_loc, ppc_str in ppc_list[:values.DEFAULT_MAX_FLIPPINGS]:
            if count == values.DEFAULT_GEN_SEARCH_LIMIT:
                break
            count = count + 1
            result_list.append(generator.generate_special_paths(con_loc, ppc_str))
    else:
        emitter.normal("\t\tstarting parallel computing")
        pool = mp.Pool(mp.cpu_count(), initializer=mute)
        for con_loc, ppc_str in ppc_list[:values.DEFAULT_MAX_FLIPPINGS]:
            if count == values.DEFAULT_GEN_SEARCH_LIMIT:
                break
            count = count + 1
            pool.apply_async(generator.generate_special_paths,
                             args=(con_loc, ppc_str),
                             callback=collect_result)
        pool.close()
        emitter.normal("\t\twaiting for thread completion")
        pool.join()
    # assert(len(result_list) == len(path_list))
    for path_list in result_list:
        for path in path_list:
            con_loc, path_smt, path_str = path
            filtered_list.append(((con_loc, path_smt, path_str), arg_list, poc_path, bin_path))
    return filtered_list


def generate_flipped_paths(ppc_list):
    global pool, result_list, expected_count
    result_list = []
    path_list = []
    filtered_list = []
    lock = None
    count = 0
    expected_count = len(ppc_list)
    ppc_list.reverse()
    if values.DEFAULT_OPERATION_MODE in ["sequential", "semi-parallel"]:
        for control_loc, ppc in ppc_list[:values.DEFAULT_MAX_FLIPPINGS]:
            if definitions.DIRECTORY_LIB in control_loc:
                continue
            if count == values.DEFAULT_GEN_SEARCH_LIMIT:
                break
            ppc_str = ppc
            if ppc_str in values.LIST_PATH_READ:
                continue
            values.LIST_PATH_READ.append(ppc_str)
            count = count + 1
            new_path = generator.generate_flipped_path(ppc)
            if new_path is None:
                continue
            new_path_str = new_path.serialize()
            ppc_len = len(str(new_path.serialize()))
            path_list.append((control_loc, new_path, ppc_len))
            if new_path_str not in values.LIST_PATH_CHECK:
                values.LIST_PATH_CHECK.append(new_path_str)
                result_list.append(oracle.check_path_feasibility(control_loc, new_path, count - 1))

    else:
        emitter.normal("\t\tstarting parallel computing")
        pool = mp.Pool(mp.cpu_count(), initializer=mute)
        thread_list = []
        for control_loc, ppc in ppc_list[:values.DEFAULT_MAX_FLIPPINGS]:
            if definitions.DIRECTORY_LIB in control_loc:
                expected_count = expected_count - 1
                continue
            if count > values.DEFAULT_GEN_SEARCH_LIMIT:
                expected_count = count
                break
            ppc_str = ppc
            if ppc_str in values.LIST_PATH_READ:
                expected_count = expected_count - 1
                continue
            values.LIST_PATH_READ.append(ppc_str)
            count = count + 1
            new_path = generator.generate_flipped_path(ppc)
            if new_path is None:
                continue
            new_path_str = new_path.serialize()
            ppc_len = len(str(new_path.serialize()))
            path_list.append((control_loc, new_path, ppc_len))
            if new_path_str not in values.LIST_PATH_CHECK:
                values.LIST_PATH_CHECK.append(new_path_str)
                abortable_func = partial(abortable_worker, oracle.check_path_feasibility, default=False, index=count-1)
                pool.apply_async(abortable_func, args=(control_loc, new_path, count - 1), callback=collect_result_timeout)
                # thread_list.append(thread)
        emitter.normal("\t\twaiting for thread completion")
        # for thread in thread_list:
        #     try:
        #         thread.get(values.DEFAULT_TIMEOUT_SAT)
        #     except TimeoutError:
        #         emitter.warning("\t[warning] timeout raised on a thread")
        #         thread.successful()
        time.sleep(1.3 * values.DEFAULT_TIMEOUT_SAT)
        pool.terminate()
    # assert(len(result_list) == len(path_list))
    for result in result_list:
        is_feasible, index = result
        if is_feasible:
            filtered_list.append(path_list[index])
    return filtered_list


def generate_symbolic_paths(ppc_list, arg_list, poc_path, bin_path):
    """
       This function will analyse the partial path conditions collected at each branch location and isolate
       the branch conditions added at each location, negate the constraint to create a new path
              ppc_list : a dictionary containing the partial path condition at each branch location
              returns a list of new partial path conditions
    """
    emitter.normal("\tgenerating new paths")
    emitter.highlight("\t\t[info] found " + str(len(ppc_list)) + " branch locations")
    path_list = []
    if values.DEFAULT_GEN_SPECIAL_PATH:
        path_list = generate_special_paths(ppc_list, arg_list, poc_path, bin_path)
    path_count = len(path_list)
    result_list = generate_flipped_paths(ppc_list)
    for result in result_list:
        path_count = path_count + 1
        path_list.append((result, arg_list, poc_path, bin_path))

    emitter.highlight("\t\tgenerated " + str(path_count) + " flipped path(s)")
    return path_list

