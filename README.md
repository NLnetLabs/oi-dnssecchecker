# OpenINTEL DNSSEC Checker Scripts

**Copyright (c) 2018-2019 NLnet Labs (https://nlnetlabs.nl/)**

All rights reserved. Distributed under a 3-clause BSD-style license. For more information, see LICENSE

## Preamble

This collection of scripts has been developed for the Swedish Internet Infrastructure Foundation (IIS), for use in their operation of the .se and .nu ccTLDs. This scripting may have broader applicability outside of IIS, but this may require additional development.

## Checks performed by the scripts

The assortment of scripts in this repository together can be used to check the DNSSEC status of all signed domains in a dataset collected by the OpenINTEL platform. The input data consists of all Avro files for the dataset for a single day, including Avro files containing TLSA records for the MX names in the dataset. For each domain in the dataset, the scripts will perform the following checks:

 - If the domain is signed (criteria: at least one ```DNSKEY``` record and and at least one ```RRSIG``` covering the ```DNSKEY``` record set)
 - If the domain has a secure delegation (criteria: at least one ```DS``` with a SHA-256 or SHA-384 hash matching one ```DNSKEY``` record)
 - If the domain meets algorithm best practices, which is either:
    - The domain uses RSA with algorithm 8 or 10, and the size of all keys is at least 2048-bits
    - The domain uses ECDSA
    - The domain uses EdDSA
 - If there is a correct signature over the ```DNSKEY``` set for every algorithm present in that set
 - If there is a correct signature over the ```SOA``` record for every algorithm present in the ```DNSKEY``` set
 - If there is a ```TLSA``` record for at least one of the ```MX``` records for the domain (checks for ```TLSA``` records for either TCP port 25, TCP port 465 or TCP port 587)
 - If there are ```TLSA``` records for all of the ```MX``` records for the domain (checks for ```TLSA``` records for either TCP port 25, TCP port 465 or TCP port 587)

### Output

The scripts output a file in JSON format, containing an array with an entry for every tested domain. Below is an example of a possible output:

```
{
	"domain": "exampledomain.cctld.", 
	"has_dnssec": true, 
	"has_secure_delegation": true, 
	"dnssec_algorithm_ok": true, 
	"dnssec_keysize_ok": true, 
	"dnssec_algorithms": [13], 
	"dnskey_sig_verifies": true, 
	"dnskey_sig_reason": "Found at least one valid RRSIG for every algorithm in RRset for exampledomain.cctld.", 
	"soa_sig_verifies": true, 
	"soa_sig_reason": "Found at least one valid RRSIG for every algorithm in RRset for exampledomain.cctld.", 
	"tlsa_one_mx": true, 
	"tlsa_all_mx": true
} 
```

As is evident from the output, this matches with the checks described above. Note well, though, that not all of the keys shown in the example above may be present in the output (if a check fails, then the key may simply not be present in the output, so the absence of a key should be treated as an indication that the check, or one of the checks it depends on, failed).

## Running the checks

### Dependencies

The scripts requires Python 3 to run, and have been tested with Python 3.6 on Ubuntu 18.04LTS. The following dependencies need to be installed (available through 'pip'):

 - ```fastavro``` >= 0.21.14
 - ```base32hex``` >= 1.0.2
 - ```ecdsa``` >= 0.13
 - ```PyNaCl``` >= 1.3.0

To install all of these requirements, execute the following from the root of this repository:

```
$ pip3 install -r requirements.txt
```

Note that the script also depends on the Python ```dateutil``` package to be installed. This is available for most distributions as a native package, for example, on an Ubuntu system the following command installs this package:

```
$ apt install python3-dateutil
```

### Configuration file

The scripts require a simple configuration file in JSON format to specify some parameters. A sample configuration file called ```example.conf``` is included in the repository, the configuration file can contain the following settings:

 - ```log_dir``` (required) - path to the directory where log files are created.
 - ```tmp_dir``` (required) - path for temporary files; the script will download the Avro files to check to this directory.
 - ```out_dir``` (required) - path where the output from the checks will be written.
 - ```multi_process_count``` (optional, defaults to 1) - number of check processes to start; the checks can be parallelised to speed them up. In case of parallelisation, set this value to the number of cores of your machine.
 - ```tld``` (required) - top-level domain to perform the checks for (e.g. "se")

### Running

When you have created an appropriate configuration file, you can now run the checks. Note that the volume on which ```tmp_dir``` resides should have sufficient free space to download **and** uncompress the Avro files. In practice this means that at the time of writing (March 2019), this volume should have at least 6GB of free space.

To run the scripts, execute the following command:

```
$ ./execute_checks.py -c <config_file>
```

Depending on your system configuration, the scripts may take several hours to run on a full set of data for the .se ccTLD (in a single core setup). Adding more cores and processes can significantly speed up execution.

### Output files

When the scripts have finished, you will have two files in the directory specified by ```out_dir```:

 - ```<tld>-results-<date>.json.bz2``` (e.g. ```se-results-2019-01-01.json.bz2```) - this contains the result for all the domains that were tested in JSON format, BZip2 compressed.
 - ```<tld>-stats-<data>.json``` (e.g. ```se-stats-2019-01-01.json```) - contains aggregate statistics about the results of all of the checks, an example is provided below.

### Statistics

The scripts also generate a file with aggregate statistics (see above). This file contains a JSON object with the following keys:

 - ```has_dnssec_no``` - number of domains that do not have DNSSEC
 - ```has_dnssec_yes``` - number of domains that are DNSSEC signed
 - ```has_ds_no``` - number of domains without a valid ```DS``` record
 - ```has_ds_yes``` - number of domains with a valid ```DS``` record
 - ```has_ds_no_algo_2_or_3``` - number of domains that have a ```DS``` but not one with a SHA-256 or SHA-384 hash
 - ```has_ds_mismatch``` - number of domains with a mismatch between the ```DS``` record set and the ```DNSKEY``` record set
 - ```dnssec_algorithm_ok``` - number of domains with a compliant DNSSEC algorithm
 - ```dnssec_algorithm_ko``` - number of domains without a compliant DNSSEC algorithm
 - ```dnssec_keysize_ok``` - number of domains with a compliant DNSSEC key size
 - ```dnssec_keysize_ko``` - number of domains without a compliant DNSSEC key size
 - ```rrsig_verify_DNSKEY_ok``` - number of domains where the ```RRSIG``` record(s) over the ```DNSKEY``` set validate(s)
 - ```rrsig_verify_DNSKEY_ko``` - number of domains where the ```RRSIG``` record(s) over the ```DNSKEY``` set do(es) not validate
 - ```rrsig_verify_SOA_ok``` - number of domains where the ```RRSIG``` record(s) over the ```SOA``` record validate(s)
 - ```rrsig_verify_SOA_ko``` - number of domains where the ```RRSIG``` record(s) over the ```SOA``` record do(es) not validate

### Logging

The scripts also produce log files. While the script is executing, it maintains a general log file that reflects the execution of all checks, and separate log files for each Avro file that checks are performed on. At the end of execution, the Avro-specific log files are consolidated into a single log file, leaving two log files:

 - ```oi-dnssecchecks-<date>-<tld>.log``` (e.g. ```oi-dnssecchecks-2019-01-01-se.log```) - the general log file.
 - ```<tld>-avrologs-<date>.log.bz2``` (e.g. ```se-avrologs-2019-01-01.log```) - the consolidated log files for the invidual Avro files.

The general log file only contains information on the progress of the checks, whereas the individual Avro log files also contain information on why, for example, signature validation for a specific domain fails.