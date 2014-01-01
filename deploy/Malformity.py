#!/usr/bin/env python

##########################################
#### - Malformity Remote Transforms - ####
## - Copyright 2013,  Malformity Labs - ##
# - @digital4rensics - @malformitylabs - #
###### - Keith@malformitylabs.com - ######
########## - License:  GPLv3 - ###########

import sys
import json
import urllib2
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
# Transform Setting: 'limit' - limits number of results, default = 10
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
def vi_hash2reg(hash):
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

# Originally written by Marcus Eddy
# Requires a transform setting called 'apikey'
# VirusTotal Domain to IP
# Returns passive IP data for a specific domain
# Input: maltego.Domain
# Output: maltego.IPv4Address
def vt_dom2ip(dom):
	TRX = MaltegoTransform()
	
	val = dom.Value
	aKey = dom.getTransformSetting('apikey')
	page = vtM('dom', val, aKey)
	
	if not page == "err":
		try:
			response_dict = json.loads(page)
			for i in range(0, len(response_dict['resolutions'])):
				ip = response_dict['resolutions'][i]['ip_address']
				Ent = TRX.addEntity('maltego.IPv4Address', ip)
		except IOError:
			TRX.addUIMessage('VT IO Error')
		except KeyError:
			TRX.addUIMessage('VT Key Error')
	else:
		TRX.addUIMessage('Error with VT Request')
		
	return TRX.returnOutput()
	
# Originally written by Marcus Eddy
# Requires a transform setting called 'apikey'
# VirusTotal IP to Domain
# Returns passive Domain data for a specific IP
# Input: maltego.IPv4Address
# Output: maltego.Domain
def vt_ip2dom(ip):
	TRX = MaltegoTransform()
	
	val = ip.Value
	aKey = ip.getTransformSetting('apikey')
	page = vtM('ip', val, aKey)
	
	if not page == "err":
		try:
			response_dict = json.loads(page)
			for i in range(0, len(response_dict['resolutions'])):
				dom = response_dict['resolutions'][i]['hostname']
				Ent = TRX.addEntity('maltego.Domain', dom)
		except IOError:
			TRX.addUIMessage('VT IO Error')
		except KeyError:
			TRX.addUIMessage('VT Key Error')
	else:
		TRX.addUIMessage('Error with VT Request')
		
	return TRX.returnOutput()

# Requires a transform setting called 'apikey'	
# VirusTotal Domain to Hash
# Returns hashes that match based on the domain search method
# Input: maltego.Domain
# Output: malformity.Hash
def vt_dom2hash(dom):
	TRX = MaltegoTransform()
	
	val = dom.Value
	aKey = dom.getTransformSetting('apikey')
	page = vtSearch(val, aKey)
	
	if not page == "err":
		try:
			data = json.loads(page)
			if data['response_code'] == 1:
				results = data['hashes']
				for result in results:
					Ent = TRX.addEntity('malformity.Hash', result)
			else:
				TRX.addUIMessage('No VT Search Results')
		except:
			TRX.addUIMessage('Error parsing VT results')
	else:
		TRX.addUIMessage('Error with VT Request')
	
	return TRX.returnOutput()
	
# Requires a transform setting called 'apikey'	
# VirusTotal IP to Hash
# Returns hashes that match based on the IP search method
# Input: maltego.IPv4Address
# Output: malformity.Hash
def vt_ip2hash(ip):
	TRX = MaltegoTransform()
	
	val = ip.Value
	aKey = ip.getTransformSetting('apikey')
	page = vtSearch(val, aKey)
	
	if not page == "err":
		try:
			data = json.loads(page)
			if data['response_code'] == 1:
				results = data['hashes']
				for result in results:
					Ent = TRX.addEntity('malformity.Hash', result)
			else:
				TRX.addUIMessage('No VT Search Results')
		except:
			TRX.addUIMessage('Error parsing VT results')
	else:
		TRX.addUIMessage('Error with VT Request')
	
	return TRX.returnOutput()
	
# Requires a transform setting called 'apikey'	
# VirusTotal Hash 2 ExifTool
# Returns ExifTool information for a given hash
# Input: malformity.hash
# Output: maltego.Phrase, malformity.Filename
# ^ Against best practice, due to be split out
def vt_hash2exif(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	aKey = hash.getTransformSetting('apikey')
	page = vtGetR(val, aKey)
	
	if not page == "err":
		try:
			data = json.loads(page)
			try:
				exif = data['additional_info']['exiftool']
			except:
				exif = 'none'
			if not exif == "none":
				try:	
					prod = exif['ProductName']
					Ent = TRX.addEntity('maltego.Phrase', prod)
				except:
					#no Product Name
					pass
				try:
					lang = exif['LanguageCode']
					Ent = TRX.addEntity('maltego.Phrase', lang)
				except:
					#no language code
					pass
				try:
					char = exif['CharacterSet']
					Ent = TRX.addEntity('maltego.Phrase', char)
				except:
					#no character set
					pass
				try:
					orig = exif['OriginalFilename']
					Ent = TRX.addEntity('malformity.Filename', orig)
				except:
					#no original name
					pass
				try:
					time = exif['Timestamp']
					Ent = TRX.addEntity('maltego.Phrase', time)
				except:
					#no timestamp
					pass
				try:
					intern = exif['InternalName']
					Ent = TRX.addEntity('maltego.Phrase', intern)
				except:
					#no internal name
					pass
				try:
					type = exif['FileType']
					Ent = TRX.addEntity('maltego.Phrase', type)
				except:
					#no filetype
					pass
				try:
					desc = exif['FileDescription']
					Ent = TRX.addEntity('maltego.Phrase', desc)
				except:
					#no file description
					pass
				try:
					copy = exif['LegalCopyright']
					Ent = TRX.addEntity('maltego.Phrase', copy)
				except:
					#no copyright data
					pass
				try:
					entry = exif['EntryPoint']
					Ent = TRX.addEntity('maltego.Phrase', entry)
				except:
					#no entry point
					pass
				try:
					ver1 = exif['FileVersionNumber']
					Ent = TRX.addEntity('maltego.Phrase', ver1)
				except:
					#no File Version Number
					pass
				try:
					ver2 = exif['ProductVersion']
					Ent = TRX.addEntity('maltego.Phrase', ver2)
				except:
					#no Product Version
					pass
		except:
			TRX.addUIMessage(data['verbose_msg'])
	else:
		TRX.addUIMessage('Error making VT Request')
				
	return TRX.returnOutput()
	
# Requires a transform setting called 'apikey'	
# VirusTotal Hash 2 NetActivity
# Returns Network Activity information for a given hash
# Input: malformity.hash
# Output: maltego.Domain, maltego.IPv4Address, maltego.URL, maltego.Port, malformity.UserAgent
# ^ Against best practice, due to be split out
def vt_hash2net(hash):
	TRX = MaltegoTransform()
	
	val = hash.Value
	aKey = hash.getTransformSetting('apikey')
	page = vtGetB(val, aKey)
	
	if not page == "err":
		try:
			data = json.loads(page)
			try:
				network = data['network']
			except:
				network = 'none'
				pass
			if not network == 'none':
				try:
					for result in network['dns']:
						dom = result['hostname']
						ip = result['ip']
						Ent = TRX.addEntity('maltego.Domain', dom)
						Ent = TRX.addEntity('maltego.IPv4Address', ip)
				except:
					pass
				try:
					for request in network['http']:
						Ent = TRX.addEntity('maltego.URL', request['uri'])
						Ent.addProperty('Short title', 'Short title', 'loose', request['uri'])
				
						Ent = TRX.addEntity('malformity.UserAgent', request['user-agent'])
						Ent = TRX.addEntity('maltego.Port', request['port'])
				except:
					pass
				try:
					for entiry in network['tcp']:
						e = entry['dst']
						if e.startswith('10.'):
							pass
						else:
							Ent = TRX.addEntity('maltego.IPv4Address', e)
				except:
					pass
		except:
			TRX.addUIMessage("Error Parsing VT Output")
	else:
		TRX.addUIMessage("Error with VT Request")
	
	TRX.returnOutput()
	
# Requires a transform setting called 'apikey'	
# VirusTotal Hash 2 PESig
# Returns PESignature information for a given hash
# Input: malformity.hash
# Output: malformity.Filename, maltego.Phrase
# ^ Against best practice, due to be split out
def vt_hash2pe(hash)
	TRX = MaltegoTransform()
	
	val = hash.Value
	aKey = hash.getTransformSetting('apikey')
	page = vtGetR(val, aKey)
	
	if not page == "err":
		try:
			data = json.loads(page)
			try:
				addinfo = data['additional_info']
			except:
				addinfo = 'none'
				pass
			if not addinfo == 'none':
				try:
					pub = addinfo['sigcheck']['publisher']
					Ent = TRX.addEntity('maltego.Phrase', pub)
				except:
					#no dns data
					pass
				try:
					prod = addinfo['sigcheck']['product']
					Ent = TRX.addEntity('maltego.Phrase', prod)
				except:
					#no product data
					pass
				try:
					desc = addinfo['sigcheck']['description']
					Ent = TRX.addEntity('maltego.Phrase', desc)
				except:
					#no description data
					pass
				try:
					orig = addinfo['sigcheck']['original name']
					Ent = TRX.addEntity('malformity.Filename', orig)
				except:
					#no original name
					pass
				try:
					sign = addinfo['sigcheck']['signers']
					Ent = TRX.addEntity('maltego.Phrase', sign)
				except:
					#no signers
					pass
				try:
					intern = addinfo['sigcheck']['internal name']
					Ent = TRX.addEntity('maltego.Phrase', intern)
				except:
					#no internal name
					pass
		except:
			TRX.addUIMessage('Error Parsing VT Output')
	else:
		TRX.addUIMessage('Error Making VT Request')
		
	TRX.returnOutput()