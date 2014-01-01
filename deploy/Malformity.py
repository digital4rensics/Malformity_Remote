#!/usr/bin/env python

##########################################
#### - Malformity Remote Transforms - ####
## - Copyright 2013,  Malformity Labs - ##
# - @digital4rensics - @malformitylabs - #
###### - Keith@malformitylabs.com - ######
########## - License:  GPLv3 - ###########

import sys
import json
from maltego import *
from helpers import *
from datetime import datetime

# Team CYMRU Hash Check
# Returns a property with results from a team CYMRU hash lookup
# Input: malformity.Hash
# Output: origin entity properties
def trx_CYMRUCheck(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	host = 'hash.cymru.com'
	
	result = whois(val, host)
	attribs = result.split()
	hsh = attribs[0]
	time = float(attribs[1])
	percent = attribs[2]
	
	if attribs[2] == "NO_DATA":
		Ent = TRX.addEntity("malformity.Hash", hsh)
		Ent.addProperty('TeamCymru', 'TeamCymru', 'loose', "Not Detected")
	else:
		Ent = TRX.addEntity("malformity.Hash", hsh)
		Ent.addProperty('Cymru Date', 'Cymru Date', 'loose', datetime.utcfromtimestamp(time))
		Ent.addProperty('Percent Detected', 'Percent Detected', 'loose', percent)
		
	return TRX.returnOutput()

# ISC ASN Report
# Returns tracked IP addresses from ISC AS Reports
# Input: maltego.AS
# Output: maltego.IPv4Address
# Optional Setting: 'limit' - limits number of results, default = 10
def isc_ASReport(asn):
	TRX = MaltegoTransform()
	val = asn.Value
	
	try:
		if asn.getTransformSetting('limit'):
			num = asn.getTransformSetting('limit')
		else:
			num = 10
	except:
		TRX.addUIMessage('Error reading setting, or setting does not exist')
		num = 10
	
	page = isc_asn(num, val)
	
	if not page == "err":
		try:
			for entry in page.findAll('data'):
				ip = entry.find('ip').text
				san = ip.replace('.0','.').replace('.0','.').lstrip('0')
				rpts = entry.find('reports').text
				tgts = entry.find('targets').text
				first = entry.find('firstseen').text
				last = entry.find('lastseen').text
				
				Ent = TRX.addEntity("maltego.IPv4Address", san)
				Ent.addProperty('ISC Min', 'ISC Min', 'loose', first)
				End.addProperty('ISC Max', 'ISC Max', 'loose', last)
				Ent.addProperty('ISC Count', 'ISC Count', 'loose', rpts)
				Ent.addProperty('ISC Attacks', 'ISC Attacks', 'loose', tgts)
		except:
			TRX.addUIMessage('Error Parsing IPs')
	else:
		TRX.addUIMessage('Error retrieving page')
		
	return TRX.returnOutput()

# ISC IP Report
# Returns attacks details of the specified IP
# Input: maltego.IPv4Address
# Output: origin entity data	
def isc_IPReport(ip):
	TRX = MaltegoTransform()
	
	val = ip.Value
	page = isc_ip(val)
	
	if not page == "err":
		try:
			atcks = page.find('attacks').text
			count = page.find('count').text
			first = page.find('mindate').text
			last = page.find('maxdate').text
			
			Ent = TRX.addEntity("maltego.IPv4Address", val)
			Ent.addProperty('ISC Min', 'ISC Min', 'loose', mindate)
			Ent.addProperty('ISC Max', 'ISC Max', 'loose', maxdate)
			Ent.addProperty('ISC Attacks', 'ISC Attacks', 'loose', atcks)
			Ent.addProperty('ISC Count', 'ISC Count', 'loose', count)
		except:
			TRX.addUIMessage('Error Parsing Data')
	else:
		TRX.addUIMessage('Error retrieving page')
		
	return TRX.returnOutput()

# Malc0de Hash Search
# Returns Malc0de results for a hash on Malc0de
# Input: malformity.Hash
# Output: maltego.IPv4Address	
def mc_HashSrch(hash):
	TRX = MaltegoTransform()
	
	if not page == "err":
		try:
			if page.find('span', {'id' : 'error'}):
				TRX.addUIMessage('No matches found in Malc0de')
			else:
				for hit in page.findAll('tr', {'class' : 'class1'}):
					temp = []
					for column in hit.findAll('td'):
						temp.append(column.text)
					
					Ent = TRX.addEntity('maltego.IPv4Address', temp[2])
					Ent.addProperty('URL', 'URL', 'loose', temp[1])
					Ent.addProperty('AS', 'AS', 'loose', temp[4])
					Ent.addProperty('Date', 'Date', 'loose', temp[0])
		except:
			TRX.addUIMessage('Error Parsing Data')
	else:
		TRX.addUIMessage('Error retrieving page')

# Malc0de IP Search
# Returns Malc0de results for an IP on Malc0de
# Input: maltego.IPv4Address
# Output: malformity.Hash	
def mc_IPSrch(ip):
	TRX = MaltegoTransform()
	
	if not page == "err":
		try:
			if page.find('span', {'id' : 'error'}):
				TRX.addUIMessage('No matches found in Malc0de')
			else:
				for hit in page.findAll('tr', {'class' : 'class1'}):
					temp = []
					for column in hit.findAll('td'):
						temp.append(column.text)
					
					Ent = TRX.addEntity('malformity.Hash', temp[6])
					Ent.addProperty('URL', 'URL', 'loose', temp[1])
					Ent.addProperty('AS', 'AS', 'loose', temp[4])
					Ent.addProperty('Date', 'Date', 'loose', temp[0])
		except:
			TRX.addUIMessage('Error Parsing Data')
	else:
		TRX.addUIMessage('Error retrieving page')
		
# Malc0de Hash to AS
# Extracts the AS property from previously returned Malc0de hashes
# Input: malformity.Hash
# Output: maltego.AS	
def mc_Hash2AS(hash):
	TRX = MaltegoTransform()
	
	if hash.getProperty('AS'):
		val = hash.getProperty('AS')
		Ent = TRX.addEntity('maltego.AS', val)
	else:
		TRX.addUIMessage('No AS Property Found for: '+hash.Value)
	
	return TRX.returnOutput()

# Malc0de Hash to URL
# Extracts the URL property from previously returned Malc0de hashes
# Input: malformity.Hash
# Output: maltego.URL	
def mc_Hash2URL(hash):
	TRX = MaltegoTransform()
	
	if hash.getProperty('URL'):
		val = hash.getProperty('URL')
		Ent = TRX.addEntity('maltego.URL', val)
		Ent.addProperty('Short title', 'Short title', 'loose', val)
	else:
		TRX.addUIMessage('No URL Property Found for: '+hash.Value)
		
	return TRX.returnOutput()

# Malc0de IP to AS
# Extracts the AS property from previously returned Malc0de IPs
# Input: maltego.IPv4Address
# Output: maltego.AS	
def mc_IP2AS(ip):
	TRX = MaltegoTransform()
	
	if ip.getProperty('AS'):
		val = ip.getProperty('AS')
		Ent = TRX.addEntity('maltego.AS', val)
	else:
		TRX.addUIMessage('No AS Property Found for: '+ip.Value)
	
	return TRX.returnOutput()

# Malc0de IP to URL
# Extracts the URL property from previously returned Malc0de IPs
# Input: maltego.IPv4Address
# Output: maltego.URL	
def mc_IP2URL(ip):
	TRX = MaltegoTransform()
	
	if ip.getProperty('URL'):
		val = ip.getProperty('URL')
		Ent = TRX.addEntity('maltego.URL', val)
		Ent.addProperty('Short title', 'Short title', 'loose', val)
	else:
		TRX.addUIMessage('No URL Property Found for: '+ip.Value)
		
	return TRX.returnOutput()	
	
# Robtex Domain to subdomains
# For a given domain, return known subdomains from robtex
# Input: maltego.Domain
# Output: maltego.Domain
def rt_GetSubs(dom):
	TRX = MaltegoTransform()
	
	val = dom.Value
	page = robtex('dns',val)
	
	if not page == "err":
		try:
			if page.find("span", {"id" : "sharedsub"}):
				section = page.find("span", {"id" : "sharedsub"}).findNext('ul')
				for entry in section.findAll("li"):
					Ent = TRX.addEntity('maltego.domain', entry.text)
			elif page.find("span", {"id" : "sharedsubv"}):
				section = page.find("span", {"id" : "sharedsubv"}).findNext('ul')
				for entry in section.findAll("li"):
					Ent = TRX.addEntity('maltego.Domain', entry.text)
			else:
				TRX.addUIMessage('No subdomains in robtex')
		except:
			TRX.addUIMessage('Error Parsing Robtex Data')
	else:
		TRX.addUIMessage('Error retrieving robtex page')
		
	return TRX.returnOutput()
	
# Robtex IP to Domains
# For a given IP address, return known domains in robtex
# Input: maltego.IPv4Address
# Output: maltego.Domain
def rt_IP2Dom(ip):
	TRX = MaltegoTransform()
	
	val = ip.Value
	page = robtex('ip', val)
	
	if not page == "err":
		try:
			section = page.find("span", {"id" : "sharedha"}).findNext('ul')
			for entry in section.findAll("li"):
				Ent = TRX.addEntity('maltego.Domain', entry.text)
		except:
			TRX.addUIMessage('Error Parsing Robtex Data')
	else:
		TRX.addUIMessage('Error retrieving robtex page')
	
	return TRX.returnOutput()

# Shadowserver AV Scan
# Original Author: Ned Moran - ned@shadowserver.org
# For a given hash, check Shadowserver AV results
# Input: malformity.Hash
# Output: origin entity data
def ss_AVScan(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	try:
		resp = urllib2.urlopen('https://innocuous.shadowserver.org/api/?query='+val).read()
	except:
		TRX.addUIMessage('Error with Shadowserver request')
		
	try:
		text = ''
		start_results = resp.find("{")
		end_results = resp.find("}")
		av_results = resp[start_results+1:end_results].replace('"','')
		text += av_results + ','
		Ent = TRX.addEntity('malformity.hash', val)
		Ent.addProperty('AV Name', 'AV Name', 'loose', text)
	except:
		TRX.addUIMessage('Error Parsing Shadowserver response')
	
	return TRX.returnOutput()
	
# ViCheck File Search
# Returns hashes for a ViCheck Phrase search and sets the filename
# Input: maltego.Phrase
# Output: malformity.Hash
def vi_FileSearch(phr):
	TRX = MaltegoTransform()
	
	val = phr.Value
	page = vic('name', val)
	
	if not page == "err":
		try:
			list = page.findAll(text='MD5:')
		except:
			TRX.addUIMessage('No ViCheck Results')
		
		try:
			for item in list:
				if item != 'none':
					Ent = TRX.addEntity('malformity.Hash', item.next.next)
					name = item.previous.previous.previous
					Ent.addProperty('Filename', 'Filename', 'loose', name)
		except:
			TRX.addUIMessage('Error Parsing ViCheck Results')
	else:
		TRX.addUIMessage('Error Retrieving ViCheck Page')
	
	return TRX.returnOutput()

# ViCheck Dropped Hash Search
# Returns dropped hashes for a ViCheck analysis and sets the filename
# Input: malformity.Hash
# Output: malformity.Hash	
def vi_hash2dhash(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	page = vic('hash', val)
	
	if not page == "err":
		try:
			list = page.find(text='Dropped File').previous.previous.parent.findAll('p')
		except:
			TRX.addUIMessage('No ViCheck Results or No Dropped Files')
		
		count = 1	
		try:
			for item in list:
				count2 = 1
				if count % 2 == 1:
					for s in split:
						if count2 % 2 == 1:
							pass
						else:
							Ent = TRX.addEntity('malformity.hash', s.text)
							name = s.previous.previous.previous.text
							Ent.addProperty('Filename', 'Filename', 'loose', name)
						count2 += 1
				elif count % 2 == 0:
					pass
				count += 1
		except:
			TRX.addUIMessage('Error Parsing ViCheck Results')
	else:
		TRX.addUImessage('Error Retrieving ViCheck Page')
		
	return TRX.returnOutput()

# ViCheck Hash to DNS
# Returns DNS Queries for a ViCheck analysis
# Input: malformity.Hash
# Output: maltego.Domain		
def vi_hash2dom(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	page = vic('hash', val)
	
	if not page == "err":
		try:
			list = page.find(text='PCAP Raw DNS Queries').previous.previous.parent.findAll('p')
		except:
			TRX.addUIMessage('No ViCheck Results or no DNS Queries')
			
		try:
			for item in list:
				if item.text != 'none':
					Ent = TRX.addEntity('maltego.Domain', item.text)
		except:
			TRX.addUIMessage('Error Parsing ViCheck Results')
	else:
		TRX.addUIMessage('Error Retrieving ViCheck Page')
		
	return TRX.returnOutput()
	
# ViCheck Hash to Filename
# Returns filenames for a ViCheck analysis
# Input: malformity.Hash
# Output: malformity.Filename
def vi_hash2Filename(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	page = vic('hash', val)
	
	if not page == "err":
		try:
			list = page.find(text='File: ').findNext('b')
		except:
			TRX.addUIMessage('No ViCheck Results or No Filename')
		
		try:
			if list.text != 'none':
				Ent = TRX.addEntity('malformity.Filename', list.text)
		except:
			TRX.addUIMessage('Error parsing ViCheck Results')
	else:
		TRX.addUIMessage('Error Retrieving ViCheck Page')
		
	return TRX.returnOutput()
	
# ViCheck Hash to Mutex
# Returns mutexes for a ViCheck analysis
# Input: malformity.Hash
# Output: malformity.Mutex
def vi_hash2mutex(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	page = vic('hash', val)
	
	if not page == "err":
		try:
			list = page.find(text='Mutex Created').previous.previous.parent.findAll('p')
		except:
			TRX.addUIMessage('No ViCheck Results or no Mutexes')
			
		try:
			for item in list:
				if item.text != 'none':
					Ent = TRX.addEntity('malformity.Mutex', item.text)
		except:
			TRX.addUIMessage('Error Parsing ViCheck Results')
	else:
		TRX.addUIMessage('Error Retrieving ViCheck Page')
		
	return TRX.returnOutput()
	
# ViCheck Hash to Registry
# Returns Registry Entries for a ViCheck analysis
# Input: malformity.Hash
# Output: malformity.RegistryEntry
def vi_hash2reg(hash)
	TRX = MaltegoTransform()
	
	val = hash.Value
	page = vic('hash', val)
	
	if not page == "err":
		try:
			list = page.find(text='Registry Item Created').previous.previous.parent.findAll('p')
		except:
			TRX.addUIMessage('No ViCheck Results or Registry Items Created')
		
		try:
			for item in list:
				if item.text != 'none':
					response += RegistryEntry(item.text)
		except:
			TRX.addUIMessage('Error Parsing ViCheck Results')
	else:
		TRX.addUIMessage('Error Retrieving ViCheck Page')
		
	return TRX.returnOutput()