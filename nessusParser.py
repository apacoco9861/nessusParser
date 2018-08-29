#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script Name: evo1_nessusParser.py
Author: Paco Chair (apacoco9861@gmail.com)
Date: 3 October 2017
Version: 0.1
"""

from argparse import ArgumentParser
from xml.dom.minidom import parse
from xml.dom import Node
from pprint import pprint
from os.path import isdir, exists, basename
from os import walk
from netaddr import IPSet
import csv
import sqlite3

#add by Paco for regex
import re
from operator import itemgetter, attrgetter, methodcaller
import collections


# Software version
PROG_VER    =    "0.2"
PROG_NAME   =    "evo1_nessusParser.py"

class nessus_parser:
    """
    Parser to perform information extraction from .nessus files format.
    """
    
    """
    Data structure to store parsed information (IP):

    _results = {
       IP_1: [ info, vuln_1, ... , vuln_N ]
       ...
       IP_N: ...
    }

    info = {
        #scan_start:        'start time of specific scan'
        #scan_stop:         'end time of specific scan'
        os:                'operating system version detected'
        hostname:          'hostname'
        netbios_name:      'netbios name'
        mac_address:       'MAC address'
    }

    vuln = {
        plugin_name:       'nessus plugin name'
        plugin_id:         'nessus plugin ID'
        plugin_type:       'local, remote, combined'
        port:              'port'
        protocol:          'protocol'
        finding:           'finding' #added by Paco
        risk:              'risk_factor'
        description:       'description'
        solution:          'suggested solution'
        service_name       'generic service name'
        cvss_base_score:   'CVSS score to format X.Y'
        cvss_vector:       'CVSS vector'
        exploit_available: 'true o false'
        metasploit:        'true o false'
        cve:               'CVE, if it exists'
    }
    """
    _results         =    None
    _iplist          =    None
    _vulnlist        =    None
    _statistics      =    None
    _DEBUG           =    False
    _filter_cvss     =    ''
    _filter_ip       =    ''
    _xml_source      =    ''
    # Max CVSS score for low vulns
    _CVSS_LOW        =    0.1
    # Min CVSS score for high vulns
    _CVSS_HIGH       =    10.0
    # Plugin Types
    _LOCAL           =    'local'
    _REMOTE          =    'remote'
    _COMBINED        =    'combined'


    #added by Paco
    #plugin_id and _finding
    _findings = None 

    #custom_cat and _catfinding
    #_catfindings1 = None 
    
    #plugin_id and custom_cat
    _findingsortlist = None
    #plugin_id and custom_cat
    #_catfindingsortlist1 = None

    # Blacklist Nessus Plugin ID
    _blacklist = [
        "20811", #Microsoft Windows Installed Software Enumeration (credentialed check)
        "34252", #Microsoft Windows Remote Listeners Enumerations (WMI)
        "34220", #Netstat Portscanner (WMI)
        "31422", #Reverse NAT/Intercepting Proxy Detection
        "11111", #RPC Services Enumeration
        "11154", #Unknown Service Detection: Banner Retrieval
        "21745", #Authentication Failure - Local Checks Not Run
        "10114", #ICMP Timestam Request Remote Date Disclosure
        "16193", #Antivirus Software Check
        "34097", #BIOS Version Information (via SMB)
        "35296", #SNMP Protocol Version Detection
        "22964", #Service Detection
        "64582", #Nestat Connection Information
        "19506", #Nessus Scan Information
        "66334", #Patch Report
        "11936", #OS Identification
        "50350", #OS Identification Failed
        "54615", #Device Type
        "55472", #Device hostname
        "84239", #Debugging Log Report
        "10287", #Traceroute Information
        "10180", #Ping the remote host
        "45590", #Common Platform Enumeration
        "56468", #Time of Last System Startup
        "57033", #Microsoft Patch Bulletin Feasibility Check
        "12053", #Host Fully Qualified Domain Name (FQDN) Resolution
        "27576", #Firewall Detection
        "56310", #Firewall Rule Enumeration
        "44401", #Microsoft Windows SMB Service Config Enumeration
        "10919", #Opened Port Re-check
        #"26917", #Nessus Cannot Access the Windows Registry
        "10736", #DCE Services Enumeration 
        "58651", #Netstat Active Connections
        "25220", #TCP/IP Timestampes Supported
        "24269", #Windows Management Instrumentation (WMI) Available
        "88145", #Host Unique identifiers
        ### Important Plugin (but too long)
        "23974", #23974, Micsoft Windows SMB Share Hosting Office Files
        "96533", #Chrome browser extension enumeration
        "60119", #Microsoft Windows SMB Share Permissions Enumeration
        "42880", #SSL/TLS Renegotiation Handshakes MiTM Plantext Data Injection
        "89058", #SSL DROWN Attack vulnerability (Decrypting RSA with Obsolete and Weaknened eNcryption)
        "35450", #DNS Server Spoofed Request Amplification DDoS
        "10539", #DNS Server Recursive Query Cache Poisoning Weakness
        "24260", #HyperText Transfer Protocol (HTTP) Information

    ]
    # Vulnerabilities filtered by blacklist
    _blacklist_hit = 0

    # Finding Category (by Vulnerability [plugin])
    #added by Paco
    #plugin_id and _finding
    _findings = {}
    #_catfindings1 = {}
    #plugin_id and custom_cat
    _findingsortlist = {}
    #_catfindingsortlist1 = {}

    #finding counter
    #added by Paco
    _finding = 1
    #_catfinding = 1


    #added by Paco
    _riskfactorlist = { #for custom risk rating
        "Critical":1,
        "High":1,
        "Medium":2,
        "Low":3,
        "None":4,
    }
    #added by Paco
    _risknamelist = { #for custom risk rating
        "Cleartext":"1",
        "Telnet":"1",
        "FTP":"2",
        "Unencrypted":"1",
        "Insecure":"1",
        "Virtual Machine":"3",
    }
    
    _idgrouplist = { #grouping multiple items ONLY
            #plugin_id
        "11219":"Discovery Results", #Nessus SYN scanner 
        "63620":"Discovery Results", #Windows Product Key Retrieval
        "46180":"Discovery Results", #Additional DNS Hostname
        "11154":"Unknown Service Detection", #Unknown Service Detection
        "10897":"Informational", #Microsoft Windows - Users Information : Disabled Accounts    
        "10898":"Account Management", #Microsoft Windows - Users Information : Never Changed Password   
        "10899":"Account Management", #Microsoft Windows - Users Information : User Has Never Logged In 
        "10913":"Informational", #Microsoft Windows - Local Users Information : Disabled Accounts   
        "10895":"Informational", #Microsoft Windows - Users Information : Automatically Disabled Accounts 
        "10911":"Informational", #Microsoft Windows - Local Users Information : Automatically Disabled Accounts 
        "10900":"Informational", #Microsoft Windows - Users Information : Passwords Never Expire 
        "10914":"Account Management", #Microsoft Windows - Local Users Information : Never Changed Passwords  
        "10915":"Account Management", #Microsoft Windows - Local Users Information : User Has Never Logged In
        "10916":"Account Management", #Microsoft Windows - Local Users Information : Passwords Never Expire 
        "65057":"Insecure Configuration", #Insecure Windows Service Permissions
        "11157":"Trojan Horse Detection", #Trojan Horse Detectioni (req51)
        "42263":"Unencrypted Telnet Server", #Unencrypted Telnet Server (req23,req651)
        "44065":"Unencrypted Non-console Access", #Plaintext Disclosure (req23,req651)
        "11411":"Backup Files Disclosure", #Backup Files Disclosure (req951)
        "66173":"Discovery Results", #RDP Screenshot
        "41028":"Default Settings", #SNMP Agent Default Community Name (public)
        "84047":"Hyper-V Virtual Machine Detection",
        "26928":"SSL Cipher Suites Vulnerabilities",
        "42873":"SSL Cipher Suites Vulnerabilities",
        "94437":"SSL Cipher Suites Vulnerabilities",
        "65821":"SSL Cipher Suites Vulnerabilities",
        "81606":"SSL Cipher Suites Vulnerabilities",
        "83875":"SSL Cipher Suites Vulnerabilities",
        "83738":"SSL Cipher Suites Vulnerabilities",
        "20007":"Early TLS Implementation",
        "78479":"Early TLS Implementation",
        "104743":"Early TLS Implementation",
        "57690":"Terminal Services Encryption Level Is Not FIPS-140 Compliant",
        "30218":"Terminal Services Encryption Level Is Not FIPS-140 Compliant",
        "58453":"Terminal Services Encryption Level Is Not FIPS-140 Compliant",
        "60108":"SSL Certificate Chain contains Weak RSA Keys",
        "69551":"SSL Certificate Chain Contains RSA Keys Less Than 2048 bits",
        "18405":"Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness",
        "45411":"SSL Certificate with Wrong Hostname",
        "51192":"SSL Certificate Cannot Be Trusted",
        "35291":"SSL Certificate Signed Using Weak Hashing Algorithm",
        "15901":"SSL Certificate Expiry",
        "57582":"SSL Self-Signed Certificate",
        "100464":"SMB Vulnerability",
        "57608":"SMB Vulnerability",
        "10092":"FTP Server Detection",
        "90317":"SSH Vulnerability",
        "71049":"SSH Vulnerability",
        "70658":"SSH Vulnerability",
        "62565":"TLS CRIME Vulnerability",
    } 

    _namegrouplist = { #plugin_name
        "MS":"Microsoft System Update",
        "KB":"Microsoft System Update",
        "Cisco IOS Software":"Cisco Multiple Vulnerabilities",
        "HP System Management":"HP System Management Homepage Multiple Vulnerabilities",
        "IBM Domino":"IBM Domino Multiple Vulnerabilities",
        "OpenSSL":"Openssl Multiple Vulnerabilities",
	"VMware Virtual Machine":"VMware Virtual Machine",
        "VMware vCenter Server":"VMware vCenter Server Multiple Vulnerabilities",
        "Detection":"Discovery Results",
    } 


    def __init__(self, filename_xml):
        if filename_xml == None or filename_xml == "":
            print "[!] No filename specified!"
            exit(1)
 
        # Parse input values in order to find valid .nessus files
        self._xml_source = []
        if isdir(filename_xml):
            if not filename_xml.endswith("/"):
                filename_xml += "/"
            # Automatic searching of files into specified directory
            for path, dirs, files in walk(filename_xml):
                for f in files:
                    if f.endswith(".nessus"):
                        self._xml_source.append(filename_xml + f)
                break
        elif filename_xml.endswith(".nessus"):
            if not exists(filename_xml):
                print "[!] File specified '%s' not exist!" % filename_xml
                exit(3)
            self._xml_source.append(filename_xml)

        if not self._xml_source:
            print "[!] No file .nessus to parse was found!"
            exit(3)

        # Dictionary to store information
        self._results = {}

        # For each .nessus file found...
        for report in self._xml_source:
            # Parse and extract information
            self._parse_results(report)


    def _parse_results(self, file_report):
        
        #added by Paco
        #db = sqlite3.connect('hysan')
        #c = db.cursor()
        # Automatic parse of .nessus file
        dom = parse(file_report)
        
        # For each host in report file, it extracts information
        for host in dom.getElementsByTagName('ReportHost'):
            # Get IP address
            ip = host.getAttribute('name')
            if ip == "":
                continue # Error getting IP address, skip!
            else:
                self._results[ip] = []
                
            # Parse information of selected node
            for item in host.childNodes:        
                if item.nodeName == 'HostProperties':
                    item_info = {
                        #'scan_start':   '',
                        #'scan_stop':    '',
                        'os':           '',
                        'hostname':     '',
                        'netbios_name': '',
                        'mac_address':  '',
                    }
                    for properties in item.childNodes:
                        if properties.attributes is None: continue
                        
                        # Extract generic information
                        #if properties.getAttribute('name') == 'HOST_START':
                        #    item_info['scan_start'] = properties.childNodes[0].nodeValue
                            
                        #if properties.getAttribute('name') == 'HOST_END':
                        #    item_info['scan_stop'] = properties.childNodes[0].nodeValue

                        if properties.getAttribute('name') == 'operating-system':
                            item_info['os'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'host-fqdn':
                            item_info['hostname'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'netbios-name':
                            item_info['netbios_name'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'mac-address':
                            item_info['mac_address'] = properties.childNodes[0].nodeValue
                            
                    # Add information extracted to data structure
                    self._results[ip].append(item_info)

                                                      
                # Information extraction
                if item.nodeName == 'ReportItem':
                    if item.attributes is None: continue
                    
                    # Skip specific vulnerability if it is into a blacklist
                    if item.getAttribute('pluginID') in self._blacklist:
                        self._blacklist_hit += 1
                        continue
                    
                    vuln = {
                        'plugin_name':       '',
                        'plugin_id':         '',
                        'plugin_type':       '',
                        'plugin_output':     '',
                        'port':              '',
                        'protocol':          '',
                        'custom_cat':        '', #added by Paco
                        'finding':           '', #added by Paco
                        'category':          '', #added by Paco
                        'risk_factor':       '',
                        'description':       '',
                        'solution':          '',
                        'service_name':      '',
                        'cvss_base_score':   '0.0',
                        'cvss_vector':       '',
                        'exploit_available': '',
                        'metasploit':        '',
                        'cve':               '',
                        }

                    # Extract generic vulnerability information
                    vuln['plugin_name'] = item.getAttribute('pluginName')
                    vuln['plugin_id'] = item.getAttribute('pluginID')
                    vuln['port'] = item.getAttribute('port')
                    vuln['protocol'] = item.getAttribute('protocol')
                    vuln['risk_factor'] = item.getAttribute('risk_factor')
                    vuln['description'] = item.getAttribute('description')
                    vuln['service_name'] = item.getAttribute('svc_name')

                    #added by Paco
                    #set category (1. compare plugin_in, 2. regex plugin_name) if 
                    if vuln['plugin_id'] in self._idgrouplist:
                        vuln['category'] = self._idgrouplist[vuln['plugin_id']]
                        
                    #if vuln['plugin_id'] not in self._idgrouplist:
                    else:
                        for key in self._namegrouplist:
                            if bool(re.search(key,vuln['plugin_name'])):
                                vuln['category'] = self._namegrouplist[key]
                                #print "Found Category: %s" % vuln['category']
                                break
                            else:
                                vuln['category'] = "NO_CATEGORY"

                                
                                #print "Category Not Found"
                                #break
                        #vuln['category'] = self._namegrouplist[key]


                    # No another information about vulnerability, continue!
                    if len(item.childNodes) == 0: continue
                    
                    # Extract detailed vulnerability information
                    for details in item.childNodes:
                        if details.nodeName == 'description':
                            vuln['description'] = details.childNodes[0].nodeValue
                            
                        if details.nodeName == 'solution':
                            vuln['solution'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'plugin_type':
                            vuln['plugin_type'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'plugin_output':
                            vuln['plugin_output'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'risk_factor':
                            vuln['risk_factor'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'cvss_base_score':
                            vuln['cvss_base_score'] = details.childNodes[0].nodeValue
                            
                        if details.nodeName == 'cvss_vector':
                            vuln['cvss_vector'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'exploitability_ease' or details.nodeName == 'exploit_available':
                            if details.childNodes[0].nodeValue.find('true') >= 0 or details.childNodes[0].nodeValue.find('Exploits are available') >= 0:
                                vuln['exploit_available'] = 'true'
                            else:
                                vuln['exploit_available'] = 'false'

                        if details.nodeName == 'exploit_framework_metasploit':
                            if details.childNodes[0].nodeValue.find('true') >= 0:
                                vuln['metasploit'] = 'true'
                                vuln['exploit_available'] = 'true'
                            else:
                                vuln['metasploit'] = 'false'
                            
                        if details.nodeName == 'cve':
                            vuln['cve'] = details.childNodes[0].nodeValue


                    #added by Paco
                    #custom_cat {from:_riskfactorlist > Critical:1,High:1,Medium:2:,Low:3,None:4}
                    #           {from:_risknamelist}
                    for key in self._risknamelist:
                        #print "risknamelist Key: %s, Value: %s, Custom: %s" % (key, self._risknamelist[key],vuln['risk_factor'])
                        if bool(re.search(key,vuln['plugin_name'])):
                            vuln['custom_cat'] = self._risknamelist[key]
                            #print "1-RISK_NAME: %s, RISK_FACTOR %s, CUSTOM_CAT: %s" %(vuln['plugin_name'],vuln['risk_factor'],vuln['custom_cat'])
                            break
                        else:
                            continue
                            #print "NO_CUSTOM_CAT-risknamelist"
                    if vuln['custom_cat'] is '':
                        for key in self._riskfactorlist:
                            #print "riskfactorlist Key: %s, Value: %s, Custom: %s" % (key,self._riskfactorlist[key],vuln['risk_factor'])
                            if bool(re.search(vuln['risk_factor'],key)):
                                vuln['custom_cat'] = self._riskfactorlist[key]
                                #print "2-RISK_NAME: %s, RISK_FACTOR %s, CUSTOM_CAT: %s" %(vuln['plugin_name'],vuln['risk_factor'],vuln['custom_cat'])
                            else:
                                continue
                                #print "3-RISK_NAME: %s, RISK_FACTOR %s, CUSTOM_CAT: %s" %(vuln['plugin_name'],vuln['risk_factor'],vuln['custom_cat'])

                    # added by Paco (add custom_cat and plugin_name to _findingsortlist
                    #if vuln['plugin_name'] not in self._findingsortlist:
                    #    self._findingsortlist[vuln['plugin_name']] = vuln['custom_cat']
                    #else:
                    #    continue

                    #print "Custom_CAT: %s, Plugin_name: %s" % (self._findingsortlist[vuln['plugin_name']], vuln['plugin_name'])
                    # Store information extracted

                    #if vuln['category'] not in self._catfindingsortlist1:
                    #    self._catfindingsortlist1[vuln['category']] = vuln['custom_cat']
                    #else:
                    #    continue

                    self._results[ip].append(vuln)

                    #c.execute("INSERT INTO nessus VALUES(counter_id,host,mac,hostname,netbios_name,os,port,protocol,service,vuln['risk_factor'],vuln['custom_cat'],vuln['category'],vuln['plugin_name'],vuln['plugin_id'],vuln['description'],vuln['solution'],pluginType,vuln['cvss_base_score'],vector,vuln['cve'],exploit,metasploit)")
                    #c.execute("INSERT INTO nessus VALUES(counter_id,host,mac,hostname,netbios_name,os,port,protocol,service,'High','1','test','testname','3321','long description','solution','local','10.0','232l','cve','yes','yes')")

                    #c.commit()

                    #if key not in self._vulnlist:
                    #    self._vulnlist[key] = vuln['plugin_name']
                    #    self._vulnlist[key].append(ip)
                    #else:
                    #    self._vulnlist[key].append(ip)
                    
                # End 'ReportItem'
            # End node parsing
        # Release open resource
        self._close(dom)
        #c.close()
        #added by paco
        #sort _findingsortlist and define finding order
        #for key in collections.OrderedDict(sorted(self._findingsortlist.items(), reverse=True, key=lambda t:t[1])):
        #for key in collections.OrderedDict(sorted(self._findingsortlist.items(), key=lambda t:t[1])):
        #    #print "%s: %s" % (key,self._findingsortlist[key])
        #    if key not in self._findings:
        #        self._findings[key] = self._finding
        #        print "Finding ID: %s, Name: %s" % (self._finding, key)
        #        self._finding += 1
        #    else:
        #        print "else Finding ID: %s, Name: %s" % (self._finding, key)


        #for catkey in collections.OrderedDict(sorted(self._catfindingsortlist1.items(), key=lambda y:y[1])):

        #    if catkey not in self._catfindings1:
        #        self._catfindings1[catkey] = self._catfinding
        #        print "CAT Finding ID: %s, Name: %s" % (self._catfinding, catkey)
        #        self._catfinding += 1
        #    else:
        #        print "CAT NOT FOUND"

    def _close(self, dom):
        if dom:
            dom.unlink()

    #def save_csv_report(self, filename, cvss_min='0.1', cvss_max='10.0', only_local=False, delim=','):
    def save_csv_report(self, filename, delim=','):
        db = sqlite3.connect(filename+".db")
        c = db.cursor()

        #c.execute("DELETE FROM nessus")
        c.execute("drop table if exists nessus")
        c.execute('''create table nessus(ID integer,MAC_Address varchar(17),Hostname text,NetBIOS text,OS text,IP varchar(15),Port varchar(5),Protocol varchar(4),Service varchar(10), CVE varchar(10), CVSS_Score real,Exploit_Available varchar(3),Metasploit_Available varchar(3),Plugin_Output text,Risk_Level varchar(6),Custom_Risk_Level varchar(1),Category varchar(20),Subcategory varchar(20),Findings varchar(3),Vuln_Name varchar(50),Vuln_Desc text,Remediation text,Access_Type varchar(6),Plugin_ID varchar(6),CVSS_Vector varchar(20));''')
        #c.execute("INSERT INTO nessus VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", params)
        # Automatic parse of .nessus file
        """
        Save extracted information into csv file format
        """
        counter_id = 1
        counter_vulns = 0
        counter_local = 0
        counter_remote = 0
        
        if not filename.endswith('.csv'):
            filename += '.csv'
        writer = csv.writer(open(filename, 'wb'), delimiter=delim)
        # Print CVS header
        writer.writerow([
            "ID",
            "MAC Address",
            "Hostname","NetBIOS Name","Operating System",
            "IP","Port","Protocol","Service","CVE","CVSS Score","Exploit Available", "Metasploit Available","Output","Risk Level",
            "Custom Risk Level","Category","Subcategory","Findings",
            "Vulnerability Name",
            "Vulnerability Description",
            "Remediation",
            "Access Type","Plugin ID",
            "CVSS Vector",
        ])
       

#        c.execute('''create table nessus(id integer,mac varchar(17),hostname text,net_bios text,os text,ip varchar(15),port varchar(5),protocol varchar(4),service varchar(10), cve varchar(10), cvss_score real,exploit varchar(3),metasploit varchar(3),Plugin_Output text,risk varchar(6),custom_risk varchar(1),category varchar(20),vuln_name varchar(50),vuln_desc text,remediation text,access_type varchar(6),plugin_id varchar(6),cvss_vector varchar(20),);''')
        # Loop hosts
        for host in self._results.keys():
            info = []
            # ID
            info.append(counter_id)

            # IP
            #info.append(host)

            #MAC ADDRESS
            mac = self._results[host][0]['mac_address']
            if mac is '':
                mac = "TBC_MAC"
                info.append(mac)
            else:
                info.append(mac)

            # HOSTNAME
            hostname = self._results[host][0]['hostname']
            if hostname is '':
                hostname = "TBC_HOSTNAME"
                info.append(hostname)
            else:
                info.append(hostname)

            netbios = self._results[host][0]['netbios_name']
            if netbios is '':
                netbios = "NO_NETBIOS"
                info.append(netbios)
            else:
                info.append(netbios)

            #OS
            os = self._results[host][0]['os']
            if os is '':
                os = "TBC_OS"
                info.append(os)
            else:
                info.append(os)

            # IP
            info.append(host)

            
            # Sort vulnerabilities by CVSS score
            #for vuln in sorted(self._results[host][1:], key=lambda cvss: float(cvss['cvss_base_score']), reverse=True):
            for vuln in sorted(self._results[host][1:]):
                info = info[0:6]
                if vuln['plugin_type'] == self._LOCAL:
                    counter_local += 1
                else:
                    counter_remote += 1
                    
                # PORT
                port = vuln['port']
                info.append(port)
                # PROTOCOL
                protocol = vuln['protocol']
                info.append(protocol)
                # SERVICE
                service = vuln['service_name']
                if service is '':
                    service = "TBC_SERVICE"
                    info.append(service)
                else:
                    info.append(service)

                # CVE
                cves=vuln['cve']
                info.append(cves)

                # CVSS SCORE
                cvssbase=vuln['cvss_base_score']
                info.append(cvssbase)

                # Exploit Available
                exploit = vuln['exploit_available']
                metasploit = vuln['metasploit']
                if exploit is 'true':
                    info.append("Yes")
                else:
                    info.append("No")
                if metasploit is 'true':
                    info.append("Yes")
                else:
                    info.append("No")
                
                # OUTPUT
                pluginoutput=vuln['plugin_output']
                info.append(pluginoutput)

                # RISK
                riskfactor=vuln['risk_factor']
                info.append(riskfactor)

                # CUSTOM_RISK
                customcat=vuln['custom_cat']
                info.append(customcat)

                #CATEGORY
                categories=vuln['category']
                info.append(categories)

                #Subcateogry
                subcategory=''
                info.append(subcategory)
                #Findings
                findings=''
                info.append(findings)


                #CATEGORY_FINDING
                #findingcategory = self._catfindings1[vuln['category']]
                #if findingcategory is '':
                #    findingcategory = "NO_CAT_ID"
#                    info.append(self._catfindings[vuln['category']])
                #    info.append(findingcategory)
                #else:
                #    info.append(findingcategory)
                #print findingcategory
                #FINDING
                #info.append(self._findings[vuln['plugin_name']])
                # VULN NAME
                pluginname=vuln['plugin_name']
                info.append(pluginname)
                #PLUGIN_ID
                #pluginid=vuln['plugin_id']
                #info.append(pluginid)
                # VULN DESC
                descriptions=vuln['description']
                info.append(descriptions)
                # REMEDIATION
                solutions=vuln['solution']
                info.append(solutions)
                # OUTPUT
                #pluginoutput=vuln['plugin_output']
                #info.append(pluginoutput)
                # ACCESS TYPE (LOCAL/REMOTE/COMBINED)
                pluginType = vuln['plugin_type']
                if pluginType == "local":
                    pluginType = "Local"
                if pluginType == "remote":
                    pluginType = "Remote"
                if pluginType == "combined":
                    pluginType = "Combined"
                info.append(pluginType)
                #PLUGIN_ID
                pluginid=vuln['plugin_id']
                info.append(pluginid)
                # CVSS SCORE
                #cvssbase=vuln['cvss_base_score']
                #info.append(cvssbase)
                # CVSS VECTOR (Remove 'CVSS#' preamble)
                vector = vuln['cvss_vector']
                if vector.find("#") != -1:
                    vector = vector.split("#")
                    if len(vector) > 1:
                        vector = vector[1]
                    else:
                        vector = vuln['cvss_vector']
                info.append(vector)
                # CVE
                #cves=vuln['cve']
                #info.append(cves)
                
                # Exploit Available
                #exploit = vuln['exploit_available']
                #metasploit = vuln['metasploit']
                #if exploit is 'true':
                #    info.append("Yes")
                #else:
                #    info.append("No")
                #if metasploit is 'true':
                #    info.append("Yes")
                #else:
                #    info.append("No")
                writer.writerow([item.encode("utf-8") if isinstance(item, basestring) else item for item in info])

                params = (counter_id,mac,hostname,netbios,os,host,port,protocol,service,cves,cvssbase,exploit,metasploit,pluginoutput,riskfactor,customcat,categories,subcategory,findings,pluginname,descriptions,solutions,pluginid,pluginType,vector)

                #c.execute("INSERT INTO nessus VALUES(counter_id,host,mac,hostname,netbios_name,os,port,protocol,service, vuln['risk_factor'],vuln['custom_cat'],vuln['category'],vuln['plugin_name'],vuln['plugin_id'],vuln['description'],vuln['solution'],pluginType,vuln['cvss_base_score'],vector,vuln['cve'],exploit,metasploit)")
                #select custom_risk,ip,port,protocol,service,vuln_name,output from nessus where vuln_name in (select distinct vuln_name from nessus where custom_risk in (1,2,3) order by custom_risk) order by custom_risk,vuln_name,ip;
                #select vuln_name,vuln_desc,remediation from nessus where vuln_name in (select distinct vuln_name from nessus where custom_risk in (1,2,3) order by custom_risk) order by custom_risk,vuln_name,ip;

                #c.execute('''create table nessus(id integer,ip varchar(15),mac varchar(17),hostname text,net_bios text,os text,port varchar(5),protocol varchar(4),service varchar(10),risk varchar(6),custom_risk varchar(1),category varchar(20),vuln_name varchar(50),plugin_id varchar(6),vuln_desc text,remediation text,output text,access_type varchar(6),cvss_score real,cvss_vector varchar(20),cve varchar(2),exploit varchar(3),metasploit varchar(3));''')
                c.execute("INSERT INTO nessus VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", params)
                db.commit()
                counter_vulns += 1
                counter_id += 1
                info[0] = counter_id

        db.close()
        # Print reports parsed
        print "[*] Information extracted from:"
        for report in self._xml_source:
            print "\t[+] %s" % basename(report)
            
        # Prints total vulns wrote
        print "[*] CSV delimiter used: \t\t'%s'" % delim
        print "[*] Total targets parsed: \t\t%d" % len(self._results.keys())
        print "[*] Local vulnerabilities: \t\t%d" % counter_local
        print "[*] Remote vulnerabilities:\t\t%d" % counter_remote
        print "[*] Blacklist vulnerabilities:\t\t%d" % self._blacklist_hit
        print "[*] Total considered vulnerabilities: \t%d" % counter_vulns
        
# Entry point
if __name__ == "__main__":

    # Arguments parser
    cmdline = ArgumentParser(description="%s performs information extraction from .nessus files and creates a customized output. (Compatible with Nessus v5 release)" % PROG_NAME,
                             version=PROG_VER,
                             epilog="Developed by Paco Chair  (Paco Chair)"
                             )
    cmdline.add_argument("-i",
                         metavar="[dir|.nessus]",
                         help="Report exported in .nessus format. If directory is specified, will be parsed all .nessus files found. (not recursive)",
                         required=True,
                         )
    #cmdline.add_argument("-o",
    cmdline.add_argument("-o",
                         metavar="[filename]",
                         help="Save results into csv report.",
                         )
    # Parse arguments provided
    args = cmdline.parse_args()
    
    # If not operation required, exit.
    if not args.o:
        print "[!] No operation specified!"
        print ""
        # Show help
        cmdline.print_help()
        exit(2)

    # Process command line
    parser = nessus_parser(args.i)

    # Save into csv file
    if args.o:
        parser.save_csv_report(args.o, delim=',')
    # Exit successfully
    exit(0)
