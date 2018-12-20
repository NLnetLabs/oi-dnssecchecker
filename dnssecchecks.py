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
import oilog

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
		return True

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

	return True

##
# Verify the signature(s) on an RRset
#
# This test passes if there is a valid RRSIG with
# every algorithm in the DNSKEY set.
##

def verify_signatures(fqdn, rec_dict, result_dict, rrset, verify_key, reason_key):
	result_dict[verify_key] = False
	result_dict[reason_key] = "Domain does not have a DNSKEY set"

	if (fqdn, 'DNSKEY') not in rec_dict:
		return True

	dnskey_set = rec_dict[(fqdn, 'DNSKEY')]

	dnskeys = []
	dnskey_algorithms = set()

	for rec in dnskey_set:
		if type(rec) is oidnstypes.OI_DNSKEY_rec:
			dnskeys.append(rec)
			dnskey_algorithms.add(rec.algorithm)

	rrset_sigs = []
	rrset_rrs = []

	for rec in rrset:
		if type(rec) is oidnstypes.OI_RRSIG_rec:
			rrset_sigs.append(rec)
		else:
			rrset_rrs.append(rec)

	if len(rrset_sigs) == 0:
		result_dict[reason_key] = "RRset does not contain RRSIG record(s)"
		return True

	if len(dnskeys) == 0:
		result_dict[reason_key] = "No DNSKEYs found"
		return True

	succ = False
	reason = ""

	valid_algorithms = set()

	for rrsig in rrset_sigs:
		succ, reason = dnssecfn.verify_sig(rrset_rrs, dnskeys, rrsig)

		if succ:
			valid_algorithms.add(rrsig.algorithm)

	if valid_algorithms != dnskey_algorithms:
		result_dict[reason_key] = "Did not find a valid RRSIG with every algorithm in RRset for {}".format(rrsig.fqdn)
		oilog.log_warn('Failed to find a valid RRSIG with every algorithm for {} RRset for {}'.format(rrsig.type_covered, rrsig.fqdn))
		return True

	result_dict[verify_key] = True
	result_dict[reason_key] = "Found at least one valid RRSIG for every algorithm in RRset for {}".format(rrsig.fqdn)

	return True

##
# Verify the signature(s) on the DNSKEY set
#
# This test passes if there is a valid RRSIG with
# every algorithm in the DNSKEY set.
##

def check_dnskey_sig_verify(fqdn, rec_dict, result_dict):
	dnskey_rrset = []

	for rec in rec_dict[(fqdn, 'DNSKEY')]:
		if type(rec) is oidnstypes.OI_DNSKEY_rec:
			dnskey_rrset.append(rec)
		if type(rec) is oidnstypes.OI_RRSIG_rec and rec.type_covered == 'DNSKEY':
			dnskey_rrset.append(rec)

	return verify_signatures(fqdn, rec_dict, result_dict, dnskey_rrset, "dnskey_sig_verifies", "dnskey_sig_reason")

##
# Verify the signature(s) on the SOA record
#
# This test passes if there is a valid RRSIG with
# every algorithm in the DNSKEY set.
##

def check_soa_sig_verify(fqdn, rec_dict, result_dit):
	if (fqdn, 'SOA') not in rec_dict:
		oilog.log_err("No SOA record present for {}".format(fqdn))
		return True

	soa_rrset = []

	for rec in rec_dict[(fqdn, 'SOA')]:
		if type(rec) is oidnstypes.OI_SOA_rec:
			soa_rrset.append(rec)
		if type(rec) is oidnstypes.OI_RRSIG_rec and rec.type_covered == 'SOA':
			soa_rrset.append(rec)

	return verify_signatures(fqdn, rec_dict, result_dict, soa_rrset, "soa_sig_verifies", "soa_sig_reason")

##
# Active checks
##

active_checks = []
active_checks.append(check_is_dnssec_signed)
active_checks.append(check_has_secure_delegation)
active_checks.append(check_dnskey_props)
active_checks.append(check_dnskey_sig_verify)
active_checks.append(check_soa_sig_verify)

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

	result_dict[fqdn] = fqdn_result_dict
