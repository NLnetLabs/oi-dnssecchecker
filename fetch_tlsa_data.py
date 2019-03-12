#!/usr/bin/env python3
#
# Copyright (c) 2019 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Main module that will execute the checks for all Avro files
# it can find in the directory specified on the command line.
# Will spawn the specified number of threads, which defaults
# to a single thread if no thread count is specified.

import os
import sys
import datetime
import argparse
import json
from impala.dbapi import connect
import shutil
import simple_config as sc
import dateutil.parser

def fail(msg, exit_code = 1):
    sys.stderr.write('{}\n'.format(msg))
    sys.exit(exit_code)

def conn_impala():
    try:
        krb_principal   = sc.get_config_item("kerberos.principal")
        krb_keytab      = sc.get_config_item("kerberos.keytab")

        res = os.system('kinit -k -t {} {}'.format(krb_keytab, krb_principal))

        if res != 0:
            raise('Failed to obtain a Kerberos ticket')

        # OpenINTEL main node, connect over TLS with Kerberos authentication
        oi_host = sc.get_config_item("openintel.access_host")
        oi_port = int(sc.get_config_item("openintel.access_port"))

        conn = connect(host=oi_host, port=oi_port, auth_mechanism='GSSAPI', use_ssl=True)

        return conn
    except Exception as e:
        fail("Failed to connect to the OpenINTEL cluster, giving up. ({})".format(e))

def set_requestpool(cur):
    pool = sc.get_config_item("openintel.request_pool", "none")

    if pool == "none":
        return

    try:
        cur.execute('SET REQUEST_POOL="{}";'.format(pool))
    except Exception as e:
        fail('Failed to select Impala request pool ({})'.format(e))

def fetch_tlsa_data(day):
    conn = conn_impala()

    dataset = sc.get_config_item("partner.dataset")
    tld = sc.get_config_item("partner.tld")

    output_dir = sc.get_config_item("output_dir")

    try:
        os.makedirs(output_dir, exist_ok=True)
        print('Created {}'.format(output_dir))
    except Exception as e:
        fail('Failed to create {} ({})'.format(output_dir, e))

    cur = conn.cursor()

    set_requestpool(cur)

    # Fetch domains with at least one TLSA record and an RRSIG over the TLSA record
    query = ''
    query += 'SELECT DISTINCT query_name\n'
    query += 'FROM openintel.{}_warehouse_parquet\n'.format(dataset)
    query += 'WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += 'AND mx_address IS NOT NULL\n'
    query += 'AND query_name LIKE "%.{}."\n'.format(tld)
    query += 'AND mx_address IN (SELECT DISTINCT regexp_extract(query_name, "(_[^\.]+\._[^\.]+\.)(.*$)", 2) AS mx_host_name\n'
    query += '                   FROM openintel.tlsa_warehouse_parquet\n'
    query += '                   WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '                   AND query_type="TLSA"\n'
    query += '                   AND response_type="TLSA")\n'
    query += 'AND mx_address IN (SELECT DISTINCT regexp_extract(query_name, "(_[^\.]+\._[^\.]+\.)(.*$)", 2) AS mx_host_name\n'
    query += '                   FROM openintel.tlsa_warehouse_parquet\n'
    query += '                   WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '                   AND query_type="TLSA"\n'
    query += '                   AND response_type="RRSIG");\n'

    mark = datetime.datetime.now()

    sys.stdout.write('Fetching domains with at least one MX record with a TLSA record for {} from {} ... '.format(tld, dataset))
    sys.stdout.flush()

    try:
        cur.execute(query)
    except Exception as e:
        print("FAILED")
        fail('Failed to execute Impala query {} ({})'.format(query, e))

    now = datetime.datetime.now()

    print('OK ({})'.format(now - mark))

    output_name = '{}/{}-{}.txt'.format(output_dir, sc.get_config_item('tlsa_one_mx_prefix'), day)

    try:
        output_fd = open(output_name, 'w')

        for row in cur:
            output_fd.write('{}\n'.format(row[0]))

        output_fd.close()
    except Exception as e:
        fail('Failed to fetch query results and write them to {} ({})'.format(output_name, e))

    # Now find domains where all MX records have a corresponding TLSA record
    query = ''
    query += 'SELECT DISTINCT t1.query_name\n'
    query += 'FROM (SELECT DISTINCT query_name\n'
    query += '      FROM openintel.{}_warehouse_parquet\n'.format(dataset)
    query += '      WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '      AND mx_address IS NOT NULL\n'
    query += '      AND query_name LIKE "%.{}."\n'.format(tld)
    query += '      AND mx_address IN (SELECT DISTINCT regexp_extract(query_name, "(_[^\.]+\._[^\.]+\.)(.*$)", 2) AS mx_host_name\n'
    query += '                         FROM openintel.tlsa_warehouse_parquet\n'
    query += '                         WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '                         AND query_type="TLSA"\n'
    query += '                         AND response_type="TLSA")\n'
    query += '      AND mx_address IN (SELECT DISTINCT regexp_extract(query_name, "(_[^\.]+\._[^\.]+\.)(.*$)", 2) AS mx_host_name\n'
    query += '                         FROM openintel.tlsa_warehouse_parquet\n'
    query += '                         WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '                         AND query_type="TLSA"\n'
    query += '                         AND response_type="RRSIG")) AS t1\n'
    query += 'LEFT ANTI JOIN\n'
    query += '(SELECT DISTINCT query_name\n'
    query += ' FROM openintel.{}_warehouse_parquet\n'.format(dataset)
    query += ' WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += ' AND mx_address IS NOT NULL\n'
    query += ' AND query_name LIKE "%.{}."\n'.format(tld)
    query += ' AND mx_address NOT IN (SELECT DISTINCT regexp_extract(query_name, "(_[^\.]+\._[^\.]+\.)(.*$)", 2) AS mx_host_name\n'
    query += '                        FROM openintel.tlsa_warehouse_parquet\n'
    query += '                        WHERE year="{:04d}" AND month="{:02d}" AND day="{:02d}"\n'.format(day.year, day.month, day.day)
    query += '                        AND query_type="TLSA"\n'
    query += '                        AND response_type="TLSA")) AS t2\n'
    query += 'ON t1.query_name = t2.query_name;\n'

    mark = datetime.datetime.now()

    sys.stdout.write('Fetching domains where all MX records have a corresponding TLSA record for {} from {} ... '.format(tld, dataset))
    sys.stdout.flush()

    try:
        cur.execute(query)
    except Exception as e:
        print("FAILED")
        fail('Failed to execute Impala query {} ({})'.format(query, e))

    now = datetime.datetime.now()

    print('OK ({})'.format(now - mark))

    output_name = '{}/{}-{}.txt'.format(output_dir, sc.get_config_item('tlsa_all_mx_prefix'), day)

    try:
        output_fd = open(output_name, 'w')

        for row in cur:
            output_fd.write('{}\n'.format(row[0]))

        output_fd.close()
    except Exception as e:
        fail('Failed to fetch query results and write them to {} ({})'.format(output_name, e))

def main():
    argparser = argparse.ArgumentParser(description='Extract list of domains with TLSA ')

    argparser.add_argument('-c, --config', nargs=1, help='configuration file to use', type=str, metavar='config_file', dest='config_file', required=True)
    argparser.add_argument('-d, --date', nargs=1, help='date to fetch data for (defaults to yesterday)', type=str, metavar='fetch_date', dest='fetch_date', required=False)

    args = argparser.parse_args()

    # Load configuration
    sc.load_config(args.config_file[0])

    day = datetime.date.today() - datetime.timedelta(days=1)

    if args.fetch_date is not None:
        day = dateutil.parser.parse(args.fetch_date[0]).date()

    # Fetch TLSA data
    fetch_tlsa_data(day)

if __name__ == "__main__":
    main()
