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

##
# Function to read record from the specified Avro file;
# will call the supplied callback with a dictionary that
# contains all the records for a single name
##

def read_avro(filename, domrecs_callback):
	avro_fd = open(filename, 'rb')

	avro_reader = fastavro.reader(avro_fd)

	previous_fqdn = None
	rec_dict = dict()
	qname = None

	for record in avro_reader:
		qname = record['query_name']

		if qname.startswith('www.'):
			qname = qname[4:]

		if qname.startswith('123-nonexistant-dnsjedi-456.'):
			qname = qname[28:]

		if previous_fqdn is not None and qname != previous_fqdn:
			domrecs_callback(previous_fqdn, rec_dict)
			rec_dict = dict()
			previous_fqdn = qname
		elif previous_fqdn == None:
			previous_fqdn = qname

		dnsrec = oidnstypes.avro_rec_to_dnstype(record)

		if dnsrec is None:
			continue

		cur_recs = rec_dict.get((record['query_name'], record['query_type']), [])
		cur_recs.append(dnsrec)

		rec_dict[(record['query_name'], record['query_type'])] = cur_recs

	if qname is not None:
		domrecs_callback(qname, rec_dict)

	avro_fd.close()

# Test callback
def testcallback(fqdn, rec_dict):
	for k in rec_dict.keys():
		print(k, len(rec_dict[k]))

# Main entry point for testing only
def main():
	read_avro(sys.argv[1], testcallback)

	return

if __name__ == "__main__":
	main()
