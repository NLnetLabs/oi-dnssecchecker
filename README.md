# OpenINTEL DNSSEC Checker Scripts

Copyright (c) 2018 NLnet Labs (https://nlnetlabs.nl/)

All rights reserved. Distributed under a 3-clause BSD-style license. For more information, see LICENSE

## Preamble

This collection of scripts has been developed for the Swedish Internet Infrastructure Foundation (IIS), for use in their operation of the .se and .nu ccTLDs. This scripting may have broader applicability outside of IIS, but this may require additional development.

## Introduction

The assortment of scripts in this repository together can be used to check the DNSSEC status of all signed domains in a dataset collected by the OpenINTEL platform. The input data consists of all Avro files for the dataset for a single day, including Avro files containing TLSA records for the MX names in the dataset.

## Dependencies

The scripts requires Python 3 to run, and have been tested with Python 3.7. The following dependencies need to be installed (available through 'pip'):

 - avro >= 1.7.7

## Running

TBD
