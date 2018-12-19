#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Module with DNS(SEC) functions (verification, DS computing)

import oidnstypes
import hashlib
import functools
from Crypto.PublicKey import RSA		#--+
from Crypto.Signature import PKCS1_v1_5		#  |
import Crypto.Hash				#  |-> for RSA validation
import Crypto.Hash.SHA				#  |
import Crypto.Hash.SHA256			#  |
import Crypto.Hash.SHA512			#--+
import ecdsa					#----> for ECDSA validation
import nacl.encoding				#--+-> for Ed25519 validation
import nacl.signing				#--+
import eddsa_rfc8032				#----> for Ed448 validation

##
# Configuration
##

# Time to add to the expiration time of signatures when 
# validating
signature_grace_time = 7200

##
# Convert a domain name to a binary-encoded owner name
##
def str_to_owner(name):
	owner_name = bytes()

	name = name.lower().replace('\\.','\\\\')

	for label in name.split('.'):
		if len(label) > 0:
			label = label.replace('\\\\','.')
			owner_name += bytes.fromhex('%02X' % len(label))
			owner_name += bytes(label, "utf8")

	owner_name += b'\0'

	return owner_name

##
# Compute a DS for the specified DNSKEY record
##

def compute_ds(hash_obj, dnskey):
	if type(dnskey) is not oidnstypes.OI_DNSKEY_rec:
		raise Exception("Cannot compute a DS for something that is not a DNSKEY")

	hash_obj.update(str_to_owner(dnskey.fqdn))
	hash_obj.update(dnskey.towire())
	return hash_obj.digest()

##
# Verify the supplied signature for the supplied RRset
# using the supplied DNSKEY set
##

def verify_sig(rrset, dnskeyset, rrsig):
	if type(rrsig) is not oidnstypes.OI_RRSIG_rec:
		raise Exception("Can only verify RRSIG records")

	# Check expiration first
	if rrsig.timestamp < rrsig.inception - signature_grace_time:
		return False, "RRSIG is not yet valid (timestamp {}, inception {})".format(rrsig.timestamp, rrsig.inception)

	if rrsig.timestamp > rrsig.expiration + signature_grace_time:
		return False, "RRSIG has expired (timestamp {}, expiration {})".format(rrsig.timestamp, rrsig.expiration)

	# Start by collecting DNSKEYs that match the RRSIG's key tag
	matching_keys = []

	for dnskey in dnskeyset:
		if type(dnskey) is not oidnstypes.OI_DNSKEY_rec:
			continue

		if dnskey.keytag() == rrsig.keytag:
			matching_keys.append(dnskey)

	if len(matching_keys) == 0:
		return False,"Failed to find a matching DNSKEY"

	# Get the RRset in wire format first
	wire_rrset = []

	for rec in rrset:
		recwire = rec.towire()
		wire = bytes()
		wire += str_to_owner(rec.fqdn)
		wire += bytes.fromhex('%04X' % rec.rectype)
		wire += bytes.fromhex('0001') # Always use class IN
		wire += bytes.fromhex('%08X' % rrsig.original_ttl)
		wire += bytes.fromhex('%04X' % len(recwire))

		wire_rrset.append((wire, recwire))

	# Canonically order the RRset
	wire_rrset.sort(key=lambda x: x[1])

	# Construct the signature verification data
	sig_input_data = bytes()
	sig_input_data += rrsig.verification_data()

	for wire,rdata in wire_rrset:
		sig_input_data += wire
		sig_input_data += rdata

	# Do the verification
	verify_pass = False
	reason = "Could not verify signature with any of the provided DNSKEYs [{}]".format(','.join(str(k.keytag()) for k in matching_keys))

	for key in matching_keys:
		if key.algorithm in [ 5, 7, 8, 10 ]:
			# Perform RSA verification
			rsakey = RSA.construct((key.rsa_n_int, key.rsa_e_int))
			verifier = PKCS1_v1_5.new(rsakey)
			hash_fn = None

			if key.algorithm in [ 5, 7 ]:
				hash_fn = Crypto.Hash.SHA.new()
			elif key.algorithm in [ 8 ]:
				hash_fn = Crypto.Hash.SHA256.new()
			elif key.algorithm in [ 10 ]:
				hash_fn = Crypto.Hash.SHA512.new()

			hash_fn.update(sig_input_data)

			if verifier.verify(hash_fn, rrsig.signature):
				verify_pass = True
				reason = "Signature validated OK"
				break
			else:
				print('Warning: {}'.format(key.keytag()))
				print('Warning: {}'.format(hash_fn.hexdigest()))
				print('Warning: {}'.format(rsakey.encrypt(rrsig.signature, K=None)[0].hex()))
		elif key.algorithm in [ 13, 14 ]:
			# Perform ECDSA verification
			vk = None
			hash_fn = None

			if key.algorithm == 13:
				vk = ecdsa.VerifyingKey.from_string(key.wire, curve=ecdsa.NIST256p)
				hash_fn = hashlib.sha256
			elif key.algorithm == 14:
				vk = ecdsa.VerifyingKey.from_string(key.wire, curve=ecdsa.NIST384p)
				hash_fn = hashlib.sha384

			try:
				if vk.verify(rrsig.signature, sig_input_data, hash_fn):
					verify_pass = True
					reason = "Signature validated OK"
					break
			except:
				pass
		elif key.algorithm in [ 15 ]:
			# Perform Ed25519 verification
			vk = nacl.signing.VerifyKey(key.eddsa_a, encoder=nacl.encoding.RawEncoder)

			try:
				if vk.verify(sig_input_data, rrsig.signature, encoder=nacl.encoding.RawEncoder):
					verify_pass = True
					reason = "Signature validated OK"
					break
			except:
				pass
		elif key.algorithm in [ 16 ]:
			ed448_schema = eddsa_rfc8032.eddsa_obj("Ed448")

			try:
				if ed448_schema.verify(key.eddsa_a, sig_input_data, rrsig.signature):
					verify_pass = True
					reason = "Signature validated OK"
					break
			except:
				pass
		else:
			print('Warning: skipped signature validation of record for {} because algorithm {} is not supported'.format(rrset[0].fqdn, key.algorithm))

	return verify_pass, reason

