from masscanner import PortScan

import requests
from requests.structures import CaseInsensitiveDict
import urllib
import json
from urllib3.exceptions import InsecureRequestWarning
import threading
from time import sleep

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)




file = open('ranges.txt','r')
ranges = file.read()
file.close()
ranges = ranges.split('\n')
ranges.pop()

hosts = []

REQUESTS_TOTAL = 0

def LogInFile(data):
    file = open('out.txt', 'a+')
    file.write(data)
    file.close()


def Confirm(host):
    try:
        resp = requests.get('http://' + host + '/some_name_no_matter31' ,verify=False, timeout=2)
        scheme = 'http://'
        if resp.status_code == 400:
            resp = requests.get('https://' + host + '/some_name_no_matter31',verify=False, timeout=2)
            scheme = 'https://'

        try:
            content_type = response.headers['Content-Type']
        except KeyError:
            content_type = ''

        if (not ('application' in content_type or 'image' in content_type)) and (('testpayload' in resp.text)):
            print(f'ip:{host} nonfile_upload')
            LogInFile(f'{host} nonfile_upload\n')
            try:
                phptest = """ABCDEFGHIGKLMOKL"""
                content_type = {'Content-Type':'application/php'}
                resp = requests.put(scheme + host + '/testtesttest123.php',data = phptest, verify=False,headers=content_type,timeout=2)
                resp = requests.get(scheme + host + '/testtesttest123.php',verify=False, timeout=2)
                if not (phptest in resp.txt):
                    print(f'ip:{host} php_upload confirmed')
                    LogInFile(f'{host} php_upload\n')
            except:
                pass
    except:
        return 0
    
def detectUrl(host):
    try:
        resp = requests.get('http://' + host,verify=False,timeout=1,allow_redirects=False)
        return resp.url
    except requests.exceptions.ConnectTimeout:
        return 0
    except requests.exceptions.ConnectionError:
        return 0
    except requests.exceptions.ReadTimeout:
        return 0
    except requests.exceptions.ChunkedEncodingError:
        return 0
    except requests.exceptions.InvalidURL:
        return 0


def PrimaryConfirm(host):
	print(host)    
	try:
		resp = requests.put('http://' + host + '/some_name_no_matter31' ,data="testpayload",verify=False, timeout=5)
		if resp.status_code == 400:
			resp = requests.put('https://' + host + '/some_name_no_matter31' ,data="testpayload",verify=False, timeout=5)	
	except:
		#print(host)
		return 0

	if resp.status_code == 201:
		print(f'ip:{host} PUT allowed')
		LogInFile(f'{host}\n')
		Confirm(host)


def BruteLoop():
    global REQUESTS_TOTAL
    portscan = PortScan(ranges)
    while 1:
            threads = []
            hosts = portscan.GetNextHttpCommon()
            print("Next ip range scanned...")
            if hosts == 1:
                print("End of ranges, exiting...")
                return
            if hosts:
                for ip in hosts:
       	             for port in hosts[ip]['ports']:
       	       	        host = ip + ":" + str(port)
       	       	        threads.append(threading.Thread(target=PrimaryConfirm, args=(host,)))
		            
                for thread in threads:
       	       	    thread.start()
       	        for thread in threads:
       	       	    thread.join()



BruteLoop()

