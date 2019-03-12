#!/usr/bin/env python3
#
# Copyright (c) 2018-2019 NLnet Labs
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
import dateutil.parser

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

    argparser.add_argument('-c, --config', nargs=1, help='configuration file to use', type=str, metavar='config_file', dest='config_file', required=True)
    argparser.add_argument('-d, --date', nargs=1, help='date to process (defaults to yesterday)', type=str, metavar='process_date', dest='process_date', required=False)

    args = argparser.parse_args()

    # Load configuration
    try:
        sc.load_config(args.config_file[0])
    except Exception as e:
        print(e)
        sys.exit(1)

    oilog.set_log_dir(sc.get_config_item('log_dir'))

    day = datetime.date.today() - datetime.timedelta(days=1)

    if len(process_date) > 0:
        day = dateutil.parser.parse(process_date[0]).date()

    logger = oilog.OILog()
    logger.open('oi-dnssecchecks-{}.log'.format(day))

    # Download required data
    if not download_data(day):
        logger.log_err('Failed to download data for {}. bailing out'.format(day))
        sys.exit(1)

    sys.exit(0)

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
