#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# The collection of DNSSEC checks; each function has the
# same prototype and is registered in a global variable
# that contains the list of all checks. The central function
# in the module calls all registered checks in sequence with
# the data it receives through the callback from the Avro
# reader module.
#
# The check functions add one or more entries in a shared
# dictionary that contains all of the results of the
# checks.

import os
import sys
import oidnstypes
import hashlib
import dnssecfn

##
# Check DNSKEY properties
#
# This check verifies:
# - If the algorithm meets the best practice requirements
#   (RSA, ECDSA or EdDSA all with SHA256 hashing or better
#   are acceptable)
#
# - In case RSA is used if all used keys are at least
#   2048 bits in size
##

def check_dnskey_props(fqdn, rec_dict, result_dict):
	# Check if the domain has a DNSKEY at all
	if (fqdn, 'DNSKEY') not in rec_dict:
		return

	dnskey_recs = rec_dict[(fqdn, 'DNSKEY')]

	# Iterate over the DNSKEYs and check their
	# compliance; the general rules are as follows:
	#
	# - If there is any key with a compliant
	#   algorithm, then the algorithm test is
	#   marked as 'passed'
	#
	# - If there is any RSA key that is non-
	#   compliant in terms of key size, then the
	#   key size test is marked as 'failed', unless
	#   there is also a key with an approved
	#   elliptic curve algorithm
	result_dict["dnssec_algorithm_ok"] = False

	for rec in dnskey_recs:
		if type(rec) is not oidnstypes.OI_DNSKEY_rec:
			continue

		if rec.algorithm in [ 8, 10, 13, 14, 15, 16 ]:
			result_dict["dnssec_algorithm_ok"] = True

		algo_set = result_dict.get("dnssec_algorithms", set())
		algo_set.add(rec.algorithm)
		result_dict["dnssec_algorithms"] = algo_set

		if rec.algorithm in [ 1, 5, 7, 8, 10 ]:
			rsa_bitsize = len(rec.rsa_n) * 8

			bitsize_set = result_dict.get("dnssec_rsa_bitsizes", set())
			bitsize_set.add(rsa_bitsize)
			result_dict["dnssec_rsa_bitsizes"] = bitsize_set
			
			if rsa_bitsize < 2048:
				result_dict["dnssec_keysize_ok"] = False
			else:
				if "dnssec_keysize_ok" not in result_dict:
					result_dict["dnssec_keysize_ok"] = True

	algo_set = result_dict.get("dnssec_algorithms", set())

	if 13 in algo_set or 14 in algo_set or 15 in algo_set or 16 in algo_set:
		result_dict["dnssec_keysize_ok"] = True

	return True

##
# Check if the domain is DNSSEC signed at all
#
# We consider a domain to be DNSSEC signed if it has at least
# one DNSKEY record and one RRSIG record that covers the DNSKEY
##

def check_is_dnssec_signed(fqdn, rec_dict, result_dict):
	if (fqdn, 'DNSKEY') not in rec_dict:
		result_dict['has_dnssec'] = False
		return

	has_rrsig	= False
	has_dnskey	= False

	for rec in rec_dict[(fqdn, 'DNSKEY')]:
		if type(rec) is oidnstypes.OI_DNSKEY_rec:
			has_dnskey = True
		elif type(rec) is oidnstypes.OI_RRSIG_rec and rec.type_covered == 'DNSKEY':
			has_rrsig = True

	if has_rrsig and has_dnskey:
		result_dict['has_dnssec'] = True
	else:
		result_dict['has_dnssec'] = False

	return has_dnskey

##
# Check if the domain has one or more DS records and if these
# DS records match one or more DNSKEYs
#
# We consider a domain to have a secure delegation if there
# is at least one DS with a SHA256 has or better that matches
# one DNSKEY in the DNSKEY set
##

def check_has_secure_delegation(fqdn, rec_dict, result_dict):
	result_dict['has_secure_delegation'] = False

	# Exit early if there is no DS or no DNSKEY
	if (fqdn, 'DS') not in rec_dict or (fqdn, 'DNSKEY') not in rec_dict:
		return

	for ds in rec_dict[(fqdn, 'DS')]:
		if type(ds) is not oidnstypes.OI_DS_rec:
			continue

		# We only accept SHA256 or SHA384 DS records
		if ds.digest_type not in [ 2, 3]:
			continue

		for dnskey in rec_dict[(fqdn, 'DNSKEY')]:
			if type(dnskey) is not oidnstypes.OI_DNSKEY_rec:
				continue

			if dnskey.algorithm != ds.algorithm:
				continue

			dnskey_hash = None

			if ds.digest_type == 2:
				dnskey_hash = dnssecfn.compute_ds(hashlib.sha256(), dnskey)
			elif ds.digest_type == 3:
				dnskey_hash = dnssecfn.compute_ds(hashlib.sha384(), dnskey)

			if dnskey_hash == ds.digest:
				result_dict['has_secure_delegation'] = True
				return True

	return False

##
# Verify the signature(s) on the DNSKEY set
#
# This test passes if there is a valid RRSIG with
# every algorithm in the DNSKEY set.
##

def check_dnskey_sig_verify(fqdn, rec_dict, result_dict):
	result_dict["dnskey_sig_verifies"] = False
	result_dict["dnskey_sig_reason"] = "Domain does not have a DNSKEY set"

	if (fqdn, 'DNSKEY') not in rec_dict:
		return

	dnskey_set = rec_dict[(fqdn, 'DNSKEY')]

	dnskey_rrsigs = []
	dnskey_dnskeys = []
	dnskey_algorithms = set()

	for rec in dnskey_set:
		if type(rec) is oidnstypes.OI_RRSIG_rec:
			dnskey_rrsigs.append(rec)

		if type(rec) is oidnstypes.OI_DNSKEY_rec:
			dnskey_dnskeys.append(rec)
			dnskey_algorithms.add(rec.algorithm)

	if len(dnskey_rrsigs) == 0:
		result_dict["dnskey_sig_reason"] = "DNSKEY RRset does not contain RRSIG record(s)"
		return

	if len(dnskey_dnskeys) == 0:
		result_dict["dnskey_sig_reason"] = "DNSKEY RRset only contains RRSIG record(s) and no DNSKEY record(s)"
		return

	succ = False
	reason = ""

	valid_algorithms = set()

	for rrsig in dnskey_rrsigs:
		succ, reason = dnssecfn.verify_sig(dnskey_dnskeys, dnskey_dnskeys, rrsig)

		if succ:
			valid_algorithms.add(rrsig.algorithm)
		else:
			print('Warning: failed to validate RRSIG for DNSKEY set of {} with reason <<{}>>'.format(rrsig.fqdn, reason))

	if valid_algorithms != dnskey_algorithms:
		result_dict["dnskey_sig_reason"] = "Did not find a valid RRSIG with every algorithm for DNSKEY set of {} (expecting {}, got {})".format(rrsig.fqdn, dnskey_algorithms, valid_algorithms)
		return

	result_dict['dnskey_sig_verifies'] = True
	result_dict['dnskey_sig_reason'] = "Found at least one valid RRSIG for every algorithm in the DNSKEY set of {}".format(rrsig.fqdn)

	return True

##
# Active checks
##

active_checks = []
active_checks.append(check_is_dnssec_signed)
active_checks.append(check_has_secure_delegation)
active_checks.append(check_dnskey_props)
active_checks.append(check_dnskey_sig_verify)

##
# Result dictionary
##

result_dict = dict()

def clear_results():
	result_dict = dict()

def get_results():
	return result_dict

##
# Callback to be called from the Avro reader module
##

def domain_data_callback(fqdn, rec_dict):
	fqdn_result_dict = dict()

	for check in active_checks:
		if not check(fqdn, rec_dict, fqdn_result_dict):
			break

	print('{}: {}'.format(fqdn, fqdn_result_dict))

	result_dict[fqdn] = fqdn_result_dict
