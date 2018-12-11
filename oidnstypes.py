#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Module with DNS(SEC) types as supported by OpenINTEL

import ipaddress
import base64
import base32hex

##
# Generic OpenINTEL DNS record
##

class OI_DNS_rec:
	fqdn	= None

	def __init__(self, fqdn):
		self.fqdn	= fqdn

##
# Class for A records
##

class OI_A_rec(OI_DNS_rec):
	addr 	= None
	country	= None
	asn	= None

	def __init__(self, fqdn, addr_str, geo_country, asn):
		super(OI_A_rec, self).__init__(fqdn)
		self.addr 	= ipaddress.ip_address(addr_str)
		self.country	= geo_country
		self.asn	= asn

	def __str__(self):
		return '{} IN A {}'.format(self.fqdn, self.addr)

##
# Class for AAAA records
##

class OI_AAAA_rec(OI_A_rec):
	def __init__(self, fqdn, addr_str, geo_country, asn):
		super(OI_AAAA_rec, self).__init__(fqdn, addr_str, geo_country, asn)

	def __str__(self):
		return '{} IN AAAA {}'.format(self.fqdn, self.addr)

##
# Class for CNAME records
##

class OI_CNAME_rec(OI_DNS_rec):
	def __init__(self, fqdn, cname):
		super(OI_CNAME_rec, self).__init__(fqdn)
		self.cname = cname

	def __str__(self):
		return '{} IN CNAME {}'.format(self.fqdn, self.cname)

##
# Class for DNAME records
##

class OI_DNAME_rec(OI_DNS_rec):
	def __init__(self, fqdn, dname):
		super(OI_DNAME_rec, self).__init__(fqdn)
		self.dname = dname

	def __str__(self):
		return '{} IN DNAME {}'.format(self.fqdn, self.dname)

##
# Class for MX records
##

class OI_MX_rec(OI_DNS_rec):
	priority	= None
	addr		= None

	def __init__(self, fqdn, priority, addr):
		super(OI_MX_rec, self).__init__(fqdn)
		self.priority	= priority
		self.addr	= addr

	def __str__(self):
		return '{} IN MX {} {}'.format(self.fqdn, self.priority, self.addr)

##
# Class for NS records
##

class OI_NS_rec(OI_DNS_rec):
	addr	= None

	def __init__(self, fqdn, addr):
		super(OI_NS_rec, self).__init__(fqdn)
		self.addr = addr

	def __str__(self):
		return '{} IN NS {}'.format(self.fqdn, self.addr)

##
# Class for TXT records
##

class OI_TXT_rec(OI_DNS_rec):
	text	= None

	def __init__(self, fqdn, text):
		super(OI_TXT_rec, self).__init__(fqdn)
		self.text = text

	def __str__(self):
		return '{} IN TXT {}'.format(self.fqdn, self.text)

##
# Class for DS records
##

class OI_DS_rec(OI_DNS_rec):
	keytag		= None
	algorithm	= None
	digest_type	= None
	digest		= None

	def __init__(self, fqdn, keytag, algorithm, digest_type, digest):
		super(OI_DS_rec, self).__init__(fqdn)
		self.keytag		= int(keytag)
		self.algorithm		= int(algorithm)
		self.digest_type	= int(digest_type)
		self.digest		= bytes.fromhex(digest)

	def tostr(self, rectype):
		return '{} IN {} {} {} {} {}'.format(self.fqdn, rectype, self.keytag, self.algorithm, self.digest_type, self.digest.hex().upper())

	def __str__(self):
		return self.tostr('DS')

##
# Class for CDS records
##

class OI_CDS_rec(OI_DS_rec):
	def __init__(self, fqdn, keytag, algorithm, digest_type, digest):
		super(OI_CDS_rec, self).__init__(fqdn, keytag, algorithm, digest_type, digest)

	def __str__(self):
		return self.tostr('CDS')

##
# Class for DNSKEY records
##

class OI_DNSKEY_rec(OI_DNS_rec):
	flags		= None
	protocol	= None
	algorithm	= None
	rsa_n		= None
	rsa_e		= None
	ecc_x		= None
	ecc_y		= None
	dsa_t		= None
	dsa_q		= None
	dsa_p		= None
	dsa_g		= None
	dsa_y		= None
	eddsa_a		= None
	wire		= None

	def __init__(self, fqdn, flags, protocol, algorithm, rsa_n, rsa_e, ecc_x, ecc_y, dsa_t, dsa_q, dsa_p, dsa_g, dsa_y, eddsa_a, wire):
		super(OI_DNSKEY_rec, self).__init__(fqdn)
		self.flags	= flags
		self.protocol	= protocol
		self.algorithm	= algorithm

		if algorithm in [ 1, 5, 7, 8, 10 ]:
			self.rsa_n	= bytes.fromhex(rsa_n)
			self.rsa_e	= bytes.fromhex(rsa_e)

			e_len = ""

			if len(self.rsa_e) > 255:
				e_len = '00%04x' % len(self.rsa_e)
			else:
				e_len = '%02x' % len(self.rsa_e)

			self.wire	= bytes.fromhex(e_len + rsa_e + rsa_n)
		elif algorithm in [ 12, 13, 14 ]:
			self.ecc_x	= bytes.fromhex(ecc_x)
			self.ecc_y	= bytes.fromhex(ecc_y)
			self.wire	= bytes.fromhex(ecc_x + ecc_y)
		elif algorithm in [ 3, 6 ] :
			self.dsa_t	= bytes.fromhex(dsa_t)
			self.dsa_q	= bytes.fromhex(dsa_q)
			self.dsa_p	= bytes.fromhex(dsa_p)
			self.dsa_g	= bytes.fromhex(dsa_g)
			self.dsa_y	= bytes.fromhex(dsa_y)
			self.wire	= bytes.fromhex(dsa_t + dsa_q + dsa_p + dsa_g + dsa_y)
		elif algorithm in [ 15, 16 ]:
			self.eddsa_a	= bytes.fromhex(eddsa_a)
			self.wire	= self.eddsa_a
		else:
			self.wire	= bytes.fromhex(wire)
	
	def tostr(self, rectype):
		return '{} IN {} {} {} {} {}'.format(self.fqdn, rectype, self.flags, self.protocol, self.algorithm, base64.b64encode(self.wire).decode('utf8'))

	def __str__(self):
		return self.tostr('DNSKEY')

##
# Class for CDNSKEY records
##

class OI_CDNSKEY_rec(OI_DNSKEY_rec):
	def __init__(self, fqdn, flags, protocol, algorithm, rsa_n, rsa_e, ecc_x, ecc_y, dsa_t, dsa_q, dsa_p, dsa_g, dsa_y, eddsa_a, wire):
		super(OI_CDNSKEY_rec, self).__init__(fqdn, flags, protocol, algorithm, rsa_n, rsa_e, ecc_x, ecc_y, dsa_t, dsa_q, dsa_p, dsa_g, dsa_y, eddsa_a, wire)

	def __str__(self):
		return self.tostr('CDNSKEY')

##
# Class for NSEC records
##

class OI_NSEC_rec(OI_DNS_rec):
	next_domain	= None
	owner_types	= None

	def __init__(self, fqdn, next_domain, owner_types):
		super(OI_NSEC_rec, self).__init__(fqdn)
		self.next_domain	= next_domain
		self.owner_types	= owner_types

	def __str__(self):
		owner_types_str = ""

		if self.owner_types != 'none':
			owner_types_str = self.owner_types

		return '{} IN NSEC {} {}'.format(self.fqdn, self.next_domain, owner_types_str)

class OI_NSEC3_rec(OI_DNS_rec):
	hash_algorithm	= None
	flags		= None
	iterations	= None
	salt		= None
	next_hash	= None
	owner_types	= None

	def __init__(self, fqdn, hash_algorithm, flags, iterations, salt, next_hash, owner_types):
		super(OI_NSEC3_rec, self).__init__(fqdn)
		self.hash_algorithm	= hash_algorithm
		self.flags		= flags
		self.iterations		= iterations
		self.salt		= bytes.fromhex(salt)
		self.next_hash		= bytes.fromhex(next_hash)
		self.owner_types	= owner_types

	def __str__(self):
		salt_str = '-'

		if len(self.salt) > 0:
			salt_str = self.salt[1:].hex().upper()

		owner_types_str = ""

		if self.owner_types != 'none':
			owner_types_str = self.owner_types

		return '{} IN NSEC3 {} {} {} {} {} {}'.format(self.fqdn, self.hash_algorithm, self.flags, self.iterations, salt_str, base32hex.b32encode(self.next_hash[1:]).upper().strip('='), owner_types_str)

##
# Class for RRSIG records
##

class OI_RRSIG_rec(OI_DNS_rec):
	type_covered	= None
	algorithm	= None
	labels		= None
	original_ttl	= None
	inception	= None
	expiration	= None
	keytag		= None
	signer_name	= None
	signature	= None

	def __init__(self, fqdn, type_covered, algorithm, labels, original_ttl, inception, expiration, keytag, signer_name, signature):
		super(OI_RRSIG_rec, self).__init__(fqdn)
		self.type_covered	= type_covered
		self.algorithm		= int(algorithm)
		self.labels		= int(labels)
		self.original_ttl	= int(original_ttl)
		self.inception		= int(inception)
		self.expiration		= int(expiration)
		self.keytag		= int(keytag)
		self.signer_name	= signer_name
		self.signature		= bytes.fromhex(signature)

	def __str__(self):
		return '{} IN RRSIG {} {} {} {} {} {} {} {} {}'.format(self.fqdn, self.type_covered, self.algorithm, self.labels, self.original_ttl, self.expiration, self.inception, self.keytag, self.signer_name, base64.b64encode(self.signature).decode('utf8'))

# Parse the supplied Avro record and return a DNS type
def avro_rec_to_dnstype(avrorec):
	# Check integrity of the Avro record
	if 'response_type' not in avrorec:
		raise Exception('Invalid Avro record, response_type field missing')

	if 'status_code' not in avrorec:
		raise Exception('Invalid Avro record, status_code field missing')

	# Check if this is a NOERROR response
	if avrorec['status_code'] != 0:
		return None

	if avrorec['response_type'] == 'A':
		return OI_A_rec(avrorec['response_name'], avrorec['ip4_address'], avrorec['country'], avrorec['as'])
	elif avrorec['response_type'] == 'AAAA':
		return OI_AAAA_rec(avrorec['response_name'], avrorec['ip6_address'], avrorec['country'], avrorec['as'])
	elif avrorec['response_type'] == 'CNAME':
		return OI_CNAME_rec(avrorec['response_name'], avrorec['cname_name'])
	elif avrorec['response_type'] == 'DNAME':
		return OI_DNAME_rec(avrorec['response_name'], avrorec['dname_name'])
	elif avrorec['response_type'] == 'MX':
		return OI_MX_rec(avrorec['response_name'], avrorec['mx_preference'], avrorec['mx_address'])
	elif avrorec['response_type'] == 'NS':
		return OI_NS_rec(avrorec['response_name'], avrorec['ns_address'])
	elif avrorec['response_type'] == 'TXT':
		return OI_TXT_rec(avrorec['response_name'], avrorec['txt_text'])
	elif avrorec['response_type'] == 'DS':
		return OI_DS_rec(avrorec['response_name'], avrorec['ds_key_tag'], avrorec['ds_algorithm'], avrorec['ds_digest_type'], avrorec['ds_digest'])
	elif avrorec['response_type'] == 'CDS':
		return OI_CDS_rec(avrorec['response_name'], avrorec['cds_key_tag'], avrorec['cds_algorithm'], avrorec['cds_digest_type'], avrorec['cds_digest'])
	elif avrorec['response_type'] == 'DNSKEY':
		return OI_DNSKEY_rec(avrorec['response_name'], avrorec['dnskey_flags'], avrorec['dnskey_protocol'], avrorec['dnskey_algorithm'], avrorec['dnskey_pk_rsa_n'], avrorec['dnskey_pk_rsa_e'], avrorec['dnskey_pk_eccgost_x'], avrorec['dnskey_pk_eccgost_y'], avrorec['dnskey_pk_dsa_t'], avrorec['dnskey_pk_dsa_q'], avrorec['dnskey_pk_dsa_p'], avrorec['dnskey_pk_dsa_g'], avrorec['dnskey_pk_dsa_y'], avrorec['dnskey_pk_eddsa_a'], avrorec['dnskey_pk_wire'])
	elif avrorec['response_type'] == 'CDNSKEY':
		return OI_CDNSKEY_rec(avrorec['response_name'], avrorec['cdnskey_flags'], avrorec['cdnskey_protocol'], avrorec['cdnskey_algorithm'], avrorec['cdnskey_pk_rsa_n'], avrorec['cdnskey_pk_rsa_e'], avrorec['cdnskey_pk_eccgost_x'], avrorec['cdnskey_pk_eccgost_y'], avrorec['cdnskey_pk_dsa_t'], avrorec['cdnskey_pk_dsa_q'], avrorec['cdnskey_pk_dsa_p'], avrorec['cdnskey_pk_dsa_g'], avrorec['cdnskey_pk_dsa_y'], avrorec['cdnskey_pk_eddsa_a'], avrorec['cdnskey_pk_wire'])
	elif avrorec['response_type'] == 'RRSIG':
		return OI_RRSIG_rec(avrorec['response_name'], avrorec['rrsig_type_covered'], avrorec['rrsig_algorithm'], avrorec['rrsig_labels'], avrorec['rrsig_original_ttl'], avrorec['rrsig_signature_inception'], avrorec['rrsig_signature_expiration'], avrorec['rrsig_key_tag'], avrorec['rrsig_signer_name'], avrorec['rrsig_signature'])
	elif avrorec['response_type'] == 'NSEC':
		return OI_NSEC_rec(avrorec['response_name'], avrorec['nsec_next_domain_name'], avrorec['nsec_owner_rrset_types'])
	elif avrorec['response_type'] == 'NSEC3':
		return OI_NSEC3_rec(avrorec['response_name'], avrorec['nsec3_hash_algorithm'], avrorec['nsec3_flags'], avrorec['nsec3_iterations'], avrorec['nsec3_salt'], avrorec['nsec3_next_domain_name_hash'], avrorec['nsec3_owner_rrset_types'])
	elif avrorec['response_type'] in ['NSHASH', 'SPFHASH', 'TXTHASH', 'MXHASH']:
		return None
	else:
		print('Unknown record type {} for name {}'.format(avrorec['response_type'], avrorec['response_name']))
	
	return None
