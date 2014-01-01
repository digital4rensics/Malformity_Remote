#!/usr/bin/env python

##########################################
#### - Malformity Remote Transforms - ####
## - Copyright 2013,  Malformity Labs - ##
# - @digital4rensics - @malformitylabs - #
###### - Keith@malformitylabs.com - ######
########## - License:  GPLv3 - ###########

# This file contains a set of helper functions for the Malformity Transforms.
# Keeping them separate ensures the main transform set stays as clean as possible

import sys
import socket
import urllib
import urllib2
from BeautifulSoup import BeautifulSoup

def whois(query, hostname):
    """Perform initial lookup with TLD whois server
    then, if the quick flag is false, search that result 
    for the region-specifc whois server and do a lookup
    there for contact details
    
    Taken from: http://code.activestate.com/recipes/577364/
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 43))
    s.send(query + "\r\n")
    response = ''
    while True:
        d = s.recv(4096)
        response += d
        if not d:
            break
    s.close()

    return response
    
def isc_ip(ip):
	url = 'http://isc.sans.edu/api/ip/' + ip
	try:
		resp = urllib2.urlopen(url)
		html = resp.read()
		page = BeautifulStoneSoup(html)
	except:
		page = "err"
		
	return page
	
def isc_asn(num,asn):
	url = 'http://isc.sans.edu/api/asnum/'+str(num)+'/' + asn
	try:
		resp = urllib2.urlopen(url)
		html = resp.read()
		page = BeautifulSoup(html)
	except:
		page = "err"
	
	return page
	
def malc0de(term):
	url = 'http://malc0de.com/database/index.php?&search=' + term
	try:
		resp = urllib2.urlopen(url)
		html = resp.read()
		page = BeautifulSoup(html)
	except:
		page = "err"
		
	return page

def robtex(choice, val):
	url = 'http://www.robtex.com/'+choice+'/'+val+'.html'
	try:
		resp = urllib2.urlopen(url)
		html = resp.read()
		page = BeautifulSoup(html)
	except:
		page = "err"
		
	return page	
	
def vic(data, type):
	#Build Request based on type
	if type == 'hash':
		url = 'https://vicheck.ca/md5query.php?hash=' + data
	elif type == 'mutex':
		url = 'https://vicheck.ca/searchsb.php?mutex=' + data
	elif type == 'network':
		url = 'https://www.vicheck.ca/searchsb.php?server=' + data
	elif type == 'name':
		url = 'https://www.vicheck.ca/searchsb.php?filename=' + data
	else:
		pass
	
	#Retrieve page and create BS entity
	try:
		report = urllib2.urlopen(url)
		html = report.read()
		page = BeautifulSoup(html)
	except:
		page = "err"
		
	return page
	
def vtM(check, val, key)
	try:
		if check == 'dom':
			url = 'https://www.virustotal.com/vtapi/v2/domain/report'
			parameters = {'domain': val, 'apikey': key}
		elif check == 'ip':
			url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
			parameters = {'ip': val, 'apikey': key}
			
		page = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
	except:
		page = "err"
		
	return page
	
def vtSearch(val, key)
	try:
		url = 'https://www.virustotal.com/vtapi/v2/file/search'
		params = {'apikey':key, 'query':val}
		page = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
	except:
		page = "err"
		
	return page
	
def vtGetB(val, key)
	try:
		url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
		params = {'apikey':key, 'hash':hash}
		page = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
	except:
		page = "err"
		
	return page
	
def vtGetR(val, key)
	try:
		url = 'https://www.virustotal.com/vtapi/v2/file/report'
		params = {'apikey':key, 'resource':val, 'allinfo':1}
		page = urllib2.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
	except:
		page = "err"
		
	return page