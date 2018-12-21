#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Module to read and parse Avro files

import os
import sys
import fastavro
import oidnstypes
import oilog
import dnssecchecks

##
# Log the statistics for this Avro file
##

def logstats(logger, stats_dict):
	keys = list(stats_dict.keys())
	keys.sort()

	for key in keys:
		logger.log_info('{}: {}'.format(key, stats_dict[key]))

##
# Function to read record from the specified Avro file;
# will call the supplied callback with a dictionary that
# contains all the records for a single name
##

def read_avro(filename, domrecs_callback, result_dict, stats_dict, skip = 0):
	logger = oilog.OILog()
	logger.open_for_avro(filename)
	recs = 0
	avro_fd = open(filename, 'rb')

	avro_reader = fastavro.reader(avro_fd)

	previous_fqdn = None
	rec_dict = dict()
	qname = None

	if skip > 0:
		logger.log_info("Skipping {} records".format(skip))

	for record in avro_reader:
		recs += 1

		if recs < skip:
			continue

		if recs % 100000 == 0:
			logger.log_info('Read {} records from {}'.format(recs, filename))
			logstats(logger, stats_dict)

		qname = record['query_name']

		if qname.startswith('www.'):
			qname = qname[4:]

		if qname.startswith('123-nonexistant-dnsjedi-456.'):
			qname = qname[28:]

		if previous_fqdn is not None and qname != previous_fqdn:
			domrecs_callback(logger, previous_fqdn, rec_dict, result_dict, stats_dict)
			rec_dict = dict()
			previous_fqdn = qname
		elif previous_fqdn == None:
			previous_fqdn = qname

		dnsrec = oidnstypes.avro_rec_to_dnstype(logger, record)

		if dnsrec is None:
			continue

		cur_recs = rec_dict.get((record['query_name'], record['query_type']), [])
		cur_recs.append(dnsrec)

		rec_dict[(record['query_name'], record['query_type'])] = cur_recs

	if qname is not None:
		domrecs_callback(logger, qname, rec_dict, result_dict, stats_dict)

	logger.log_info('Read {} records from {}'.format(recs, filename))

	logstats(logger, stats_dict)

	avro_fd.close()
	logger.close()
