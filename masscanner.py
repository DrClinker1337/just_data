import masscan
import json

COMMON_HTTP_PORTS = "80,88,443,8000,8080,8443,8050"


class PortScan():
	def __init__(self, ip_blocks, ports=""):
		self.blocks = ip_blocks
	
		
	def GetNextHttpCommon(self):
		try:
			block = self.blocks.pop()
		except IndexError:
			return 1
	
		mas = masscan.PortScanner()
		mas.scan(block, ports=COMMON_HTTP_PORTS, arguments='--max-rate 100')
		#print(mas.scan_result)
	
		result = {}
		scan_result = json.loads(mas.scan_result)
		
		if scan_result["scan"]:
			for host in scan_result["scan"]:
				result[host] = {"ports":[]}
				for port in scan_result["scan"][host]:
					result[host]["ports"].append(port["port"])
			
			return result
		else:
			return 0


