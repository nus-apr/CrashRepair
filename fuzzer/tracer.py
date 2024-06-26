import shlex
import utils
import env
import subprocess
from bisect import bisect_left
from collections import defaultdict
import time # (YN: added import for proces killing timeout)
import logging # (YN: added to log timeouts)
import tempfile
import os
import signal

DEVNULL = open(os.devnull, 'w')


def ifTracer(cmd_list):
	if time.time() >= utils.GlobalEndTime:
		return []

	_, trace_filename = tempfile.mkstemp(suffix=".trace")

	# craft tracing command
	tracer_cmd_list = [env.dynamorio_path, '-c', env.iftracer_path, '--'] + cmd_list + ['2>&1', '>', trace_filename]
	tracer_cmd = " ".join(tracer_cmd_list)
	# logging.info("Trace command: %s" % tracer_cmd)

	p1 = subprocess.Popen(tracer_cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)

	# (YN: added timeout handling)
	t_end = time.time() + utils.SubProcessTimeout
	while True:
		if time.time() >= t_end:
			break
		if time.time() >= utils.GlobalEndTime:
			break
		if p1.poll() is not None:
			break
		time.sleep(1)

	if p1.poll() is None:
		logging.warn('ifTracer timeout occured with > %s sec' % str(utils.SubProcessTimeout))
		p1.terminate()
		time.sleep(5)
		if p1.poll() is None:
			p1.kill()
			time.sleep(5)
	out, err = p1.communicate()

	# logging.info("finished running trace command. parsing trace output...")

	# TODO check for errors

	# parse the output
	if_list = []
	with open(trace_filename, "r") as fh:
		for aline in fh:
			if '0x00000000004' in aline:
				t = aline.split(' => ')
				if_list.append(t[0])

	# destroy the temporary trace file
	os.remove(trace_filename)
	return if_list


def exe_bin(cmd_list):
	global SubProcessTimeout

	if time.time() >= utils.GlobalEndTime:
		return bytes(0), bytes(0)

	logging.info("Input command: %s" % ' '.join(cmd_list))
	p1 = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	# (YN: added timeout handling)
	t_end = time.time() + utils.SubProcessTimeout
	while True:
		if time.time() >= t_end:
			break
		if time.time() >= utils.GlobalEndTime:
			break
		if p1.poll() is not None:
			break
		time.sleep(1)
	
	if p1.poll() is None:
		logging.warn('exe_bin timeout occured with > %s sec' % str(utils.SubProcessTimeout))
		p1.terminate()
		time.sleep(5)
		if p1.poll() is None:
			p1.kill()
			time.sleep(5)

	out, err = p1.communicate()
	return out, err

def readCBR(cmdFile):
	listAddr = []
	lines = open(cmdFile, 'r').readlines()
	cmdline = lines[0].rstrip('\n')
	cmdlist = [env.dynamorio_path, '-c', env.libcbr_path, '--']

	for each in shlex.split(cmdline):
		cmdlist.append(each)

	p1 = subprocess.Popen(cmdlist, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p1.communicate()

	for aline in out.split('\n'):
		items = aline.split(':')

		if '0x' == items[0][0:2]:

			if not items[0] in listAddr:
				listAddr.append('0x' + items[0].lstrip('0x').lstrip('0'))

	# print(listAddr)
	return listAddr

def tcheckIf(flineNumberDict, name, insID, fileBoundRangesList, fileBoundIndexList, fileAddrDict, lineAddrDict):
	''' Search for 10 addresses behind the one found'''
	# print(lineNumberDict)
	found = False

	if not (name in lineAddrDict):

		fileToSearch = ''
		if not (name in fileAddrDict):
			index = bisect_left(fileBoundRangesList, int(name, 16)) - 1
			fileAddrDict[name] = fileBoundIndexList[index]
			fileToSearch = fileBoundIndexList[index]
		else:
			fileToSearch = fileAddrDict[name]

		for i in range(50):
			tnameInt = int(name, 16) - i
			tname = hex(tnameInt).rstrip('L')

			if tname in flineNumberDict[fileToSearch]:
				found = True
				lineAddrDict[name] = (flineNumberDict[fileToSearch][tname], fileToSearch)
				return [insID, flineNumberDict[fileToSearch][tname], name, fileToSearch]

	else:

		return [insID, lineAddrDict[name][0], name, lineAddrDict[name][1]]

	# if not found:
	#     for i in range(10):
	#         tname = hex(int(name, 16) + i).rstrip('L')

	#         if tname in lineNumberDict:
	#             found = True
	#             return [insID, lineNumberDict[tname]]

	return None

def findIfOrder(flineNumberDict, cmdFile, fileBoundRangesList, fileBoundIndexList):

    ifCollections = []
    linesCBR = readCBR(cmdFile)
    fileAddrDict = {}
    lineAddrDict = {}

    for i in range(len(linesCBR)):
        addr = linesCBR[i]
        ifCollections.append(tcheckIf(flineNumberDict, addr, i, fileBoundRangesList, fileBoundIndexList, fileAddrDict, lineAddrDict))

    idx_list = []
    line_list = []
    nameDict = defaultdict(str)

    for item in ifCollections:
        if item == None:
            pass
        else:
            idx_list.append(item[0])
            line_list.append(item[1])
            nameDict[item[2]]= (item[1], item[3])

    return idx_list, line_list, nameDict

def findIfSrcInOrderDyn(binFilePath, srcFilePath, flineNumberDict, fileBoundRangesList, fileBoundIndexList,
						cmdFile='cmd.txt', process_id=0, timeout=-1):
	# start = datetime.now()

	# flineNumberDict, fileBoundRangesList, fileBoundIndexList = getMainAddr(binFilePath, srcFilePath)
	''' Get the linenumbers of conditional statements in the same file for which you got the line numbers, in cmpLineNumbers '''
	idxList, cmpLineList, nameDict = findIfOrder(flineNumberDict, cmdFile, fileBoundRangesList,
												 fileBoundIndexList)  # need to save both idxList, cmpLineList
	srcLineList = []

	fnameDict = {}
	addrDict = {}
	fnameSet = set()
	addrDictRev = {}

	i = 0
	fp = open('tempDr/m%d.out' % process_id, 'w')
	for key, value in nameDict.iteritems():
		# fnameSet.add(value)
		addrDict[i] = key
		fnameDict[(key, value[0])] = value[1]
		addrDictRev[key] = i

		i += 1

	for key, value in nameDict.iteritems():
		fp.write("%s %d\n" % (str(int(key, 16)), int(value[0])))

	fp.close()

	timeout = 5
	if timeout > 0:
		cmdlist = ['timeout', str(timeout), env.dynamorio_path, '-client', env.iflinetracer_path, str(process_id), '--']
	else:
		cmdlist = [env.dynamorio_path, '-client', env.iflinetracer_path, str(process_id), '--']
	lines = open(cmdFile, 'r').readlines()
	cmdline = lines[0].rstrip('\n')

	for each in shlex.split(cmdline):
		cmdlist.append(each)

	p1 = subprocess.Popen(cmdlist, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p1.communicate()
	# print(out, err)
	ifList = []

	for aline in out.split('\n'):
		t = aline.split(' => ')
		if t[0][0:2] == '0x':
			addr = '0x' + t[0].lstrip('0x').lstrip('0')
			b = t[1].split(' ')
			ifList.append((t[0], fnameDict[(addr, b[0])], b[0], b[1]))

	return ifList
