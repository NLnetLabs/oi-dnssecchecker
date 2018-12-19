#!/usr/bin/env python3
#
# Copyright (c) 2018 NLnet Labs
# Licensed under a 3-clause BSD license, see LICENSE in the
# distribution
#
# Logging module

import os
import sys
import datetime

##
# Configuration
##

oi_log_dir	= '.'

##
# Logfile file descriptor
##

oi_log_fd	= None

##
# Open the log
##

def open_log(avro_name, append = False):
	global oi_log_fd
	avro_name = avro_name.split('/')[-1].split('.')[0]
	log_name = '{}/{}.log'.format(oi_log_dir, avro_name)

	if append:
		oi_log_fd = open(log_name, 'a')
	else:
		oi_log_fd = open(log_name, 'w')

##
# Close the log
##

def close_log():
	global oi_log_fd
	if oi_log_fd is not None:
		oi_log_fd.close()

##
# Logging functions
##

def internal_log(level, msg):
	global oi_log_fd
	if oi_log_fd is not None:
		oi_log_fd.write('{} [{}] {}\n'.format(datetime.datetime.now(), level, msg))
		oi_log_fd.flush()

def log_info(msg):
	internal_log('I', msg)

def log_warn(msg):
	internal_log('W', msg)

def log_err(msg):
	internal_log('E', msg)
