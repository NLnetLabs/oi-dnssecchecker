#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Main module that will execute the checks for all Avro files
# it can find in the directory specified on the command line.
# Will spawn the specified number of threads, which defaults
# to a single thread if no thread count is specified.

import os
import sys
import avroreader
import dnssecchecks
import oilog
import datetime
import argparse
import threading
import multiprocessing as mp
import json

def avro_check_proc(logger, avro_queue, avro_dir, out_dir):
	while not avro_queue.empty():
		try:
			avro_name = avro_queue.get()
		except queue.Empty as e:
			break

		logger.log_info('Starting on {}'.format(avro_name))

		result_dict = dict()
		stats_dict = dict()

		#try:
		avroreader.read_avro('{}/{}'.format(avro_dir, avro_name), dnssecchecks.domain_data_callback, result_dict, stats_dict)
		#except Exception as e:
		#	logger.log_err('An exception occurred while processing {}'.format(avro_name))
		#	logger.log_err(e)
		#	logger.log_err('Will not write results for {}'.format(avro_name))
		#	raise e
			#continue

		out_name = avro_name.replace('.avro','.json')
		stats_name = avro_name.replace('.avro', '-stats.json')

		out_fd = open('{}/{}'.format(out_dir, out_name), 'w')

		for k in result_dict.keys():
			result = dict()
			result[k] = result_dict[k]
			out_fd.write('{}\n'.format(json.dumps(result)))

		out_fd.close()

		stats_fd = open('{}/{}'.format(out_dir, stats_name), 'w')

		stats_fd.write('{}\n'.format(json.dumps(stats_dict)))

		stats_fd.close()

		logger.log_info('Done processing {}'.format(avro_name))
		logger.log_info('Wrote results for {} to {}/{}'.format(avro_name, out_dir, out_name))
		logger.log_info('Wrote statistics for {} to {}/{}'.format(avro_name, out_dir, stats_name))

def process_avro_files(logger, avro_dir, proc_count, out_dir):
	avro_list = []

	for f in os.listdir(avro_dir):
		if f.lower().endswith('.avro'):
			avro_list.append(f)

	logger.log_info('Found {} Avro files in {}'.format(len(avro_list), avro_dir))
	logger.log_info('Writing results to {}'.format(out_dir))
	oilog.mkdir_p(out_dir)

	analysis_queue = mp.Queue()

	for a in avro_list:
		analysis_queue.put(a)

	analysis_procs = set()

	for t in range(0, proc_count):
		analysis_procs.add(mp.Process(target=avro_check_proc, args=(logger, analysis_queue, avro_dir, out_dir)))

	logger.log_info('Starting analysis processes')

	for t in analysis_procs:
		t.start()

	while len(analysis_procs) > 0:
		for t in analysis_procs:
			t.join(0.25)
			if not t.is_alive():
				analysis_procs.remove(t)
				break

def main():
	argparser = argparse.ArgumentParser(description='Perform DNSSEC checks against Avro files in a directory')

	argparser.add_argument('-d,--directory', nargs=1, help='the directory containing Avro files', type=str, metavar='avro_dir', dest='avro_dir', required=True)
	argparser.add_argument('-p,--processes', nargs=1, help='number of processes to start', type=int, default=1, metavar='proc_count', dest='proc_count', required=False)
	argparser.add_argument('-l,--logdir', nargs=1, help='output directory for logs', type=str, default='.', metavar='log_dir', dest='log_dir', required=False)
	argparser.add_argument('-o,--output-dir', nargs=1, help='output directory for analysis results', type=str, default='.', metavar='out_dir', dest='out_dir', required=False)

	args = argparser.parse_args()

	oilog.set_log_dir(args.log_dir[0])

	logger = oilog.OILog()
	logger.open('oi-dnssecchecks-{}.log'.format(datetime.date.today()))

	try:
		process_avro_files(logger, args.avro_dir[0], args.proc_count[0], args.out_dir[0])
	except Exception as e:
		logger.log_err('Process terminated with an exception')
		logger.log_err(e)

	logger.close()

if __name__ == "__main__":
	main()
