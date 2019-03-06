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

def avro_check_proc(logger, avro_queue, avro_dir, out_dir, tld, tlsa_one_set, tlsa_all_set):
    while not avro_queue.empty():
        try:
            avro_name = avro_queue.get()
        except queue.Empty as e:
            break

        logger.log_info('Starting on {}'.format(avro_name))

        results = []
        stats_dict = dict()

        try:
            avroreader.read_avro('{}/{}'.format(avro_dir, avro_name), tld, dnssecchecks.domain_data_callback, results, stats_dict)
        except Exception as e:
            logger.log_err('An exception occurred while processing {}'.format(avro_name))
            logger.log_err(e)
            logger.log_err('Will not write results for {}'.format(avro_name))
            raise e

        out_name = avro_name.replace('.avro','.json')
        stats_name = avro_name.replace('.avro', '-stats.json')

        out_fd = open('{}/{}'.format(out_dir, out_name), 'w')

        for result in results:
            if result['domain'] in tlsa_one_set:
                result['tlsa_one_mx'] = True

            if result['domain'] in tlsa_all_set:
                result['tlsa_all_mx'] = True

            out_fd.write('{}\n'.format(json.dumps(result)))

        out_fd.close()

        stats_fd = open('{}/{}'.format(out_dir, stats_name), 'w')

        stats_fd.write('{}\n'.format(json.dumps(stats_dict)))

        stats_fd.close()

        logger.log_info('Done processing {}'.format(avro_name))
        logger.log_info('Wrote results for {} to {}/{}'.format(avro_name, out_dir, out_name))
        logger.log_info('Wrote statistics for {} to {}/{}'.format(avro_name, out_dir, stats_name))

def process_avro_files(logger, avro_dir, proc_count, out_dir, tld, tlsa_one_set, tlsa_all_set):
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
        analysis_procs.add(mp.Process(target=avro_check_proc, args=(logger, analysis_queue, avro_dir, out_dir, tld, tlsa_one_set, tlsa_all_set)))

    logger.log_info('Starting analysis processes')

    for t in analysis_procs:
        t.start()

    while len(analysis_procs) > 0:
        for t in analysis_procs:
            t.join(0.25)
            if not t.is_alive():
                analysis_procs.remove(t)
                break

    logger.log_info('Merging individual results')
    tot_count = 0

    result_fd = open('{}/{}-results-{}.json'.format(out_dir, tld, datetime.date.today()-datetime.timedelta(days=1)), 'w')
    result_fd.write('[\n')

    for a in avro_list:
        json_name = a.replace('.avro','.json')

        logger.log_info('Merging in {}/{}'.format(out_dir, json_name))

        json_fd = open('{}/{}'.format(out_dir, json_name), 'r')
        count = 0

        for line in json_fd:
            line = line.strip('\r').strip('\n')
            result_fd.write('{},\n'.format(line))
            count += 1

        json_fd.close()
        
        logger.log_info('Merged {} results from {}/{}'.format(count, out_dir, json_name))

        tot_count += count

        os.unlink('{}/{}'.format(out_dir, json_name))

    result_fd.write(']\n')
    result_fd.close()

    logger.log_info('Done, processed {} results'.format(tot_count))

def load_tlsa_list(list_file, logger):
    tlsa_set = set()

    try:
        tlsa_fd = open(list_file, 'r')

        count = 0

        for line in tlsa_fd:
            tlsa_set.add(line.strip('\r').strip('\n'))
            count += 1

        tlsa_fd.close()

        logger.log_info('Read {} domains with TLSA records from {}'.format(count, list_file))
    except Exception as e:
        logger.log_err('Failed to load domains with TLSA records from {} ({})'.format(list_file, e))

    return tlsa_set

def main():
    argparser = argparse.ArgumentParser(description='Perform DNSSEC checks against Avro files in a directory')

    argparser.add_argument('-d, --directory', nargs=1, help='the directory containing Avro files', type=str, metavar='avro_dir', dest='avro_dir', required=True)
    argparser.add_argument('-p, --processes', nargs=1, help='number of processes to start', type=int, default=1, metavar='proc_count', dest='proc_count', required=False)
    argparser.add_argument('-l, --logdir', nargs=1, help='output directory for logs', type=str, default='.', metavar='log_dir', dest='log_dir', required=False)
    argparser.add_argument('-o, --output-dir', nargs=1, help='output directory for analysis results', type=str, default='.', metavar='out_dir', dest='out_dir', required=False)
    argparser.add_argument('-t, --tlsa-one', nargs=1, help='file containing domains with at least one MX record with a corresponding TLSA record', type=str, metavar='tlsa_one', dest='tlsa_one', required=True)
    argparser.add_argument('-T, --tlsa-all', nargs=1, help='file containing domains where all MX records have a corresponding TLSA record', type=str, metavar='tlsa_all', dest='tlsa_all', required=True)
    argparser.add_argument('-D, --tld', nargs=1, help='TLD to process', type=str, metavar='tld', dest='tld', required=True)

    args = argparser.parse_args()

    oilog.set_log_dir(args.log_dir[0])

    logger = oilog.OILog()
    logger.open('oi-dnssecchecks-{}.log'.format(datetime.date.today()-datetime.timedelta(days=1)))

    # Load TLSA sets
    tlsa_one_set = load_tlsa_list(args.tlsa_one[0], logger)
    tlsa_all_set = load_tlsa_list(args.tlsa_all[0], logger)

    try:
        process_avro_files(logger, args.avro_dir[0], args.proc_count[0], args.out_dir[0], args.tld[0], tlsa_one_set, tlsa_all_set)
    except Exception as e:
        logger.log_err('Process terminated with an exception')
        logger.log_err(e)

    logger.close()

if __name__ == "__main__":
    main()
