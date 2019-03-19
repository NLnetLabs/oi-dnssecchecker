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
import multiprocessing as mp
import json
import dateutil.parser
import simple_config as sc
import requests
import tarfile
import bz2

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

        logger.log_info('Cleaning up {}/{}'.format(avro_dir, avro_name))
        os.unlink('{}/{}'.format(avro_dir, avro_name))

def process_avro_files(logger, day, avro_dir, proc_count, out_dir, tld, tlsa_one_set, tlsa_all_set):
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

    result_name = '{}/{}-results-{}.json.bz2'.format(out_dir, tld, day)
    result_fd = bz2.open(result_name, 'wt')
    result_fd.write('[\n')

    stats_dict = dict()

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

        stats_name = a.replace('.avro', '-stats.json')

        logger.log_info('Collecting stats from {}/{}'.format(out_dir, stats_name))

        stats_fd = open('{}/{}'.format(out_dir, stats_name), 'r')

        for line in stats_fd:
            line = line.strip('\r').strip('\n')

            avro_stats = json.loads(line)

            for key in avro_stats:
                stat = stats_dict.get(key, int(0))
                stat += avro_stats[key]
                stats_dict[key] = stat

        stats_fd.close()

        os.unlink('{}/{}'.format(out_dir, stats_name))

    result_fd.write(']\n')
    result_fd.close()

    logger.log_info('Done, wrote {} results to {}'.format(tot_count, result_name))

    stats_name = '{}/{}-stats-{}.json.bz2'.format(out_dir, tld, day)

    stats_out = open(stats_name, w)

    stats_out.write('{}\n'.format(json.dumps(stats_dict)))

    stats_out.close()

    logger.log_info('Wrote statistics to {}'.format(stats_name))

    consolidated_avro_log = '{}/{}-avrologs-{}.log.bz2'.format(sc.get_config_item('log_dir'), tld, day)

    cl_fd = bz2.open(consolidated_avro_log, 'wt')

    for a in avro_list:
        log_name = '{}/{}'.format(sc.get_config_item('log_dir'), a.replace('.avro','.log'))

        log_fd = open(log_name, r)

        for line in log_fd:
            cl_fd.write(line)

        log_fd.close()

        logger.log_info('Added {} to consolidated Avro log'.format(log_name))

        os.unlink(log_name)

    cl_fd.close()

    logger.log_info('Consolidated Avro logs to {}'.format(consolidated_avro_log))

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

def cleanup_tmp_file(tmp_name):
    try:
        os.unlink('{}/{}'.format(sc.get_config_item('tmp_dir'), tmp_name))
    except:
        pass

def download_file(logger, url, out_file):
    result = False

    try:
        out_fd = open('{}/{}'.format(sc.get_config_item('tmp_dir'), out_file), 'wb')
    except Exception as e:
        logger.log_err('Failed to open output file {} in temporary directory ({})'.format(out_file, e))
        return False

    try:
        response = requests.get(url, stream = True)

        if response.status_code == 200:
            if 'Content-Length' in response.headers:
                logger.log_info('Downloading {} bytes from {}'.format(response.headers['Content-Length'], url))
            else:
                logger.log_info('Downloading {}'.format(url))

            downloaded_bytes = 0

            for chunk in response.iter_content(1024*1024):
                out_fd.write(chunk)
                out_fd.flush()
                downloaded_bytes += len(chunk)

            logger.log_info('Downloaded {} bytes from {}'.format(downloaded_bytes, url))

            result = True
        else:
            logger.log_error('GET {} returned {}'.format(url, response.status_code))
    except Exception as e:
        logger.log_err('Failed to start download from {} ({})'.format(url, e))

    out_fd.close()

    if not result:
        cleanup_tmp_file(out_file)

    return result

def download_data(logger, day):
    tar_url = 'https://data.openintel.nl/data/open-tld/{}/openintel-open-tld-{:04d}{:02d}{:02d}.tar'.format(day.year, day.year, day.month, day.day)
    tlsa_all_url = 'https://data.openintel.nl/data/open-tld/{}/tlsa/{}-tlsa-all-mx-{}.txt'.format(day.year, sc.get_config_item('tld'), day)
    tlsa_one_url = 'https://data.openintel.nl/data/open-tld/{}/tlsa/{}-tlsa-one-mx-{}.txt'.format(day.year, sc.get_config_item('tld'), day)

    logger.log_info('Fetching Avro data from {}'.format(tar_url))

    if not download_file(logger, tar_url, 'opentld-{}.tar'.format(day)):
        return False

    logger.log_info('Fetching domains with TLSA records for all MX records from {}'.format(tlsa_all_url))

    if not download_file(logger, tlsa_all_url, 'tlsa-all-{}-{}.txt'.format(sc.get_config_item('tld'), day)):
        cleanup_tmp_file('opentld-{}.tar'.format(day))
        return False

    logger.log_info('Fetching domains with TLSA records for at least one MX record from {}'.format(tlsa_one_url))

    if not download_file(logger, tlsa_one_url, 'tlsa-one-{}-{}.txt'.format(sc.get_config_item('tld'), day)):
        cleanup_tmp_file('opentld-{}.tar'.format(day))
        cleanup_tmp_file('tlsa-all-{}-{}.txt'.format(sc.get_config_item('tld'), day))
        return False

    try:
        untar = tarfile.open('{}/opentld-{}.tar'.format(sc.get_config_item('tmp_dir'), day))

        untar.extractall(sc.get_config_item('tmp_dir'))

        untar.close()
    except Exception as e:
        logger.log_err('Failed to unpack {}/{} ({})'.format(sc.get_config_item('tmp_dir'), 'opentld-{}.tar'.format(day), e))
        cleanup_tmp_file('opentld-{}.tar'.format(day))
        cleanup_tmp_file('tlsa-all-{}-{}.txt'.format(sc.get_config_item('tld'), day))
        cleanup_tmp_file('tlsa-one-{}-{}.txt'.format(sc.get_config_item('tld'), day))
        return False

    cleanup_tmp_file('opentld-{}.tar'.format(day))

    return True

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

    if args.process_date is not None:
        day = dateutil.parser.parse(args.process_date[0]).date()

    logger = oilog.OILog()
    logger.open('oi-dnssecchecks-{}-{}.log'.format(day, sc.get_config_item('tld')))

    # Download required data
    if not download_data(logger, day):
        logger.log_err('Failed to download data for {}, bailing out'.format(day))
        sys.exit(1)

    # Load TLSA sets
    tlsa_one_set = load_tlsa_list('{}/tlsa-all-{}-{}.txt'.format(sc.get_config_item('tmp_dir'), sc.get_config_item('tld'), day), logger)
    tlsa_all_set = load_tlsa_list('{}/tlsa-one-{}-{}.txt'.format(sc.get_config_item('tmp_dir'), sc.get_config_item('tld'), day), logger)

    cleanup_tmp_file('tlsa-all-{}-{}.txt'.format(sc.get_config_item('tld'), day))
    cleanup_tmp_file('tlsa-one-{}-{}.txt'.format(sc.get_config_item('tld'), day))

    try:
        process_avro_files(logger, day, sc.get_config_item('tmp_dir'), sc.get_config_item('multi_process_count', 1), sc.get_config_item('out_dir'), sc.get_config_item('tld'), tlsa_one_set, tlsa_all_set)
    except Exception as e:
        logger.log_err('Process terminated with an exception')
        logger.log_err(e)

    logger.close()

if __name__ == "__main__":
    main()
