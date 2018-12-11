#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution

import os
import sys
import fastavro
import oidnstypes

# Read and parse an Avro file

# Main entry point for testing only
def main():
	avro_fd = open(sys.argv[1], 'rb')

	avro_r = fastavro.reader(avro_fd)

	for rec in avro_r:
		dnsrec = oidnstypes.avro_rec_to_dnstype(rec)

		if type(dnsrec) is oidnstypes.OI_CDNSKEY_rec:
			print(dnsrec)

	avro_fd.close()

	return

if __name__ == "__main__":
	main()
