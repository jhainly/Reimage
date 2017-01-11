# Author:  Jeremiah Hainly
# Purpose: Quarantine or remove quarantine from Hershey endpoint. This is part of a larger script
#          that verifies the user's identity in Splunk and sends the user an email
#		   to notify of a reimage ticket being created.

import warnings
warnings.filterwarnings("ignore")

import requests
import requests.auth
import sys
import os
import ConfigParser

#################### RESOURCE PATH #######################
# Changes the resource path so that the image in the #####
# email can be referenced when compiled with pyinstaller #
# but also referenced when running in python #############
##########################################################
def resource_path(relative_path):
    # Get absolute path to resource, works for dev and for PyInstaller
    try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS
    except Exception:
		base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

parser = ConfigParser.RawConfigParser()
parser.read(resource_path('configs.ini'))

########## METHOD 1 ##############
# Submit host to SEP for Reimage #
##################################
def reimage(targetHost, targetCommand):
	print "\nConnecting to SEPM"
	# Connect to SEPM's web app port using quarantine user and refresh the access token.
	try:
		# Client ID = User Name. Client Secret = Password. Account was created via https://vmsepp01:8446/
		# Refresh token instructions at bottom of code
		response = requests.post(parser.get('sep', 'authurl'), verify=False) #remote auth=client_auth
		data = response.json()
		access_token = data['value']
		headers = {"Authorization": "bearer " + access_token}
		response = requests.get(parser.get('sep', 'wsdl'), headers=headers, verify=False)
	except:
		print "Error authenticating to SEPM server. Please verify client_id, client_secret, and refresh_token"
		sys.exit()
	print "Connected!"

	# Request the SEP GUID for a computer by passing through computer's host name via SOAP call
	try:
		headers = {"Authorization": "bearer " + access_token, 'content-type': 'text/xml', "SOAPAction": "http://client.webservice.sepm.symantec.com/getComputersByHostName"}
		body = """
		<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://client.webservice.sepm.symantec.com/">
			<soapenv:Header/>
			<soapenv:Body>
				<ns:getComputersByHostName>
					<computerHostNames>"""+targetHost+"""</computerHostNames>
				</ns:getComputersByHostName>
			</soapenv:Body>
		</soapenv:Envelope>
		"""

		# HTTP POST command. Sends the SOAP commands above
		response = requests.post(parser.get('sep', 'wsdl'),data=body,headers=headers, verify=False)

		import xmltodict
		# Writes the response to the HTTP POST to a dictionary for parsing
		doc = xmltodict.parse(response.content)
		# Access the dictionary and pull the GUIDE
		targetGUID = doc['S:Envelope']['S:Body']['ns2:getComputersByHostNameResponse']['ns2:ComputerResult']['computers']['computerId']
		# Print the GUID
		print "  " + targetHost + " SEP GUID: " + targetGUID
	except:
		# Warn the user that other tasks within the script may have been run.
		print "Unable to retrieve host GUID. Please validate hostname and be aware that I might have completed some tasks already."
		sys.exit()

	# Request quarantine / undo by passing the computer's GUID (found above) via SOAP call
	try:
		headers = {"Authorization": "bearer " + access_token, 'content-type': 'text/xml', "SOAPAction": "http://command.client.webservice.sepm.symantec.com/runClientCommandQuarantine"}

		body = """
		<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://command.client.webservice.sepm.symantec.com/">
			<soapenv:Header/>
			<soapenv:Body>
				<ns:runClientCommandQuarantine>
					<command>
						<commandType>"""+targetCommand+"""</commandType>
						<targetObjectType>COMPUTER</targetObjectType>
						<targetObjectIds>"""+str(targetGUID)+"""</targetObjectIds>
					</command>
				</ns:runClientCommandQuarantine>
			</soapenv:Body>
		</soapenv:Envelope>"""

		response = requests.post(parser.get('sep', 'wsdl'),data=body,headers=headers, verify=False)
		if targetCommand == "Quarantine":
			print "  Successfully quarantined " + targetHost
		if targetCommand == "Undo":
			print "  Successfully removed quarantine from " + targetHost
	except:
		print "Unable to quarantine. Dunno why I failed"
		sys.exit()