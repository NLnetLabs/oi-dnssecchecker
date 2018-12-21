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
import threading
import errno

##
# Configuration
##

oi_log_dir	= '.'

##
# Set the log output directory
##  

def mkdir_p(path):
        try:
                os.makedirs(path)
        except OSError as e:
                if e.errno != errno.EEXIST:
                        raise

def set_log_dir(dirname):
	global oi_log_dir
	oi_log_dir = dirname
	mkdir_p(oi_log_dir)

class OILog():
	##
	# Log file
	##

	log_fd = None
	log_lock = threading.Lock()

	##
	# Open the log
	##

	def open(self, logname, append = False):
		if append:
			self.log_fd = open('{}/{}'.format(oi_log_dir, logname), 'a')
		else:
			self.log_fd = open('{}/{}'.format(oi_log_dir, logname), 'w')
	
	def open_for_avro(self, avro_name, append = False):
		avro_name = avro_name.split('/')[-1].split('.')[0]
		log_name = '{}.log'.format(avro_name)

		self.open(log_name)
	
	##
	# Close the log
	##
	
	def close(self):
		if self.log_fd is not None:
			self.log_fd.close()
	
	##
	# Logging functions
	##
	
	def internal_log(self, level, msg):
		self.log_lock.acquire()

		if self.log_fd is not None:
			self.log_fd.write('{} [{}] {}\n'.format(datetime.datetime.now(), level, msg))
			self.log_fd.flush()

		self.log_lock.release()
	
	def log_info(self, msg):
		self.internal_log('I', msg)
	
	def log_warn(self, msg):
		self.internal_log('W', msg)
	
	def log_err(self, msg):
		self.internal_log('E', msg)
