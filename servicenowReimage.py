# Author:  Jeremiah Hainly
# Purpose: Open ServiceNow ticket to reimage user. This is part of a larger script
#          that verifies the user's identity in Splunk and sends the user an email
#		   to notify of a reimage ticket being created.

############################################################################################
#      PLEASE VERIFY THAT THIS SCRIPT IS RUNNING IN TEST BEFORE DOING ANY TEST RUNS		   #
############################################################################################


######## Imports ##########
# Import required modules #
###########################
import requests # python -m pip install requests
import re
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

# Define parser for configuration file
parser = ConfigParser.RawConfigParser()
parser.read(resource_path('configs.ini'))

################### Define Variables #############################
# Define ServiceNow URL, Hershey Proxy, and ServiceNow credentials
##################################################################
proxies = {parser.get('production_proxy','proxytype'):parser.get('production_proxy','proxyurl')}
headers = {"Content-Type":"application/json","Accept":"application/json"}

url = parser.get('production_servicenow', 'url')    		# PRODUCTION ServiceNow URL
user = parser.get('production_servicenow', 'user')			# PRODUCTION ServiceNow Username
pwd = parser.get('production_servicenow', 'pwd')			# PRODUCTION ServiceNow Password
'''
url = parser.get('development_servicenow', 'url')			# TEST ServiceNow URL
user = parser.get('development_servicenow', 'user')			# TEST ServiceNow Username
pwd = parser.get('development_servicenow', 'pwd')			# TEST ServiceNow Password
'''

############# METHOD 1 ####################
# Method to submit new ServiceNow tickets #
###########################################
def submit(targetHost, targetUser):
	# Try connecting to ServiceNow and submitting a ticket
	print "\nConnecting to ServiceNow"
	try:
		# variable "response" equal to output from HTTP POST via requests method. Use previously defined URL, auth, proxy, headers
		# Data provides information for each field in the ServiceNow ticket
		response = requests.post(url, auth=(user, pwd), proxies=proxies, headers=headers ,data='{"impact":"' + parser.get('snOptions','impact') + '","urgency":"' + parser.get('snOptions','urgency') + '","priority":"' + parser.get('snOptions','priority') + '","assignment_group":"' + parser.get('snOptions','assignment_group') + '","short_description":"Reimage Workstation: '+ str(targetHost) +'","caller_id":"'+str(targetUser)+'","contact_type":"System","incident_state":"' + parser.get('snOptions','incident_state') + '","state":"' + parser.get('snOptions','state') + '","category":"' + parser.get('snOptions','category') + '","subcategory":"' + parser.get('snOptions','subcategory') + '","comments":"' + parser.get('snOptions','teamName') + ' has identified the workstation with hostname ['+targetHost+'] as an infected workstation. Please backup the user\'s files to OneDrive and reimage the machine as soon as possible to prevent further infection on the network. After reimage, please reset the user\'s domain password."}')
	except Exception as e:
		print(e)
		# If requests method is unable to connect (Wrong password, wrong URL, wrong proxy, etc.), provide the inputs and stop the script
		print "Failed to connect to ServiceNow. Please make sure the instance is available."
		print "CONNECTION DETAILS"
		print "  ServiceNow URL: " + url
		print "  ServiceNow User: " + user
		print "  ServiceNow Password: " + pwd
		print "  Hostname: " + targetHost
		sys.exit()

	# Check for HTTP codes other than 201 (Created)
	if response.status_code != 201: 
		print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
		exit()
	else:
		# If requests method is successful, communicate it
		print "Connected!"

	# Decode the JSON response from requests method to return Incident Number
	try:
		snOutput = str(response.json())
		# Regex search the JSON response for the text "INC" and provide the text until the next non-letter character
		getSnTicket = re.search('(?<=u\WINC)\w+', snOutput)
		# regex search stores the results as a group. Let's put that incident number into a variable
		snTicket = str(getSnTicket.group(0))
		# Positive feedback
		print "  Successfully created INC" + snTicket + " to reimage " + targetHost + "\n"
	except:
		# Negative feedback if the regex fails. Stops the script
		print "\nCannot find Incident Number"
		sys.exit()

	# Give the new ServiceNow Ticket number back to be used elsewhere
	return snTicket

##################### METHOD 2 #######################
# Method to request the sysID for ServiceNow tickets #
# Used when an update to a ticket needs to be made ###
# since ServiceNow only communicates in sysID's ######
######################################################
def request(snTicket):
	# Change the URL so that it queries for the ServiceNow ticket number
	global url
	tmpurl = url + '?sysparm_query=number=INC' + snTicket #TEST SERVICENOW
	
	# Try connecting to ServiceNow and getting ticket info
	print "\nConnecting to ServiceNow"
	try:
		# variable "response" equal to output from HTTP GET via requests method. Use previously defined URL, auth, proxy, headers
		response = requests.get(tmpurl, auth=(user, pwd), proxies=proxies, headers=headers)
	except:
		# If requests method is unable to connect (Wrong password, wrong URL, wrong proxy, etc.), provide the inputs and stop the script
		print "Failed to connect to ServiceNow. Please make sure the instance is available."
		print "CONNECTION DETAILS"
		print "  ServiceNow URL: " + tmpurl
		print "  ServiceNow User: " + user
		print "  ServiceNow Password: " + pwd
		sys.exit()

	# Check for HTTP codes other than 200 (OK)
	if response.status_code != 200: 
		print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
		exit()
	else:
		# If requests method is successful, communicate it
		print "Connected!"

	# Decode the JSON response from requests method to return Incident Number
	try:
		snOutput = str(response.json())
		# Regex search the JSON response for the text "sys_id" and a few non-letter chars, then provide the text until the next non-letter character
		getSysID = re.search('(?<=u\Wsys_id\W\W\W\w\W)\w+', snOutput)
		# regex search stores the results as a group. Let's put that incident number into a variable
		sysID = str(getSysID.group(0))
		# Positive feedback
		print "  Successfully found sys_id: " + sysID + " for INC" + snTicket + "\n"
	except:
		# Negative feedback if the regex fails. Stops the script
		print "\nCould not find anything"
		sys.exit()

	# Give the sysID back to be used for the update method
	return sysID


################# METHOD 3 ###################
# Method to update old ServiceNow tickets ####
# Used when an incident exists for the issue #
##############################################
def update(sysID, targetHost, targetUser):
	# Change the URL so that it points at the sysID of the ServiceNow incident identified in the "request" method
	tmpurl = url + '/' + sysID
	
	# Try connecting to ServiceNow and updating a ticket
	print "\nConnecting to ServiceNow"
	try:
		# variable "response" equal to output from HTTP PUT via requests method. Use previously defined URL, auth, proxy, headers
		response = requests.put(tmpurl, auth=(user, pwd), proxies=proxies, headers=headers ,data='{"impact":"1","urgency":"2","priority":"2","assignment_group":"HCOD","short_description":"Reimage Workstation: '+ str(targetHost) +'","caller_id":"'+str(targetUser)+'","contact_type":"System","incident_state":"-1","category":"PC Software","subcategory":"Antivirus","comments":"Hershey Cyber Defense has identified the workstation with hostname ['+targetHost+'] as an infected workstation. Please backup the user\'s files to OneDrive and reimage the machine as soon as possible to prevent further infection on the network. After reimage, please reset the user\'s domain password."}')
	except:
		# If requests method is unable to connect (Wrong password, wrong URL, wrong proxy, etc.), provide the inputs and stop the script
		print "Failed to connect to ServiceNow. Please make sure the instance is available."
		print "CONNECTION DETAILS"
		print "  ServiceNow URL: " + tmpurl
		print "  ServiceNow User: " + user
		print "  ServiceNow Password: " + pwd
		sys.exit()

	# Check for HTTP codes other than 200 (OK)
	if response.status_code != 200: 
		print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
		exit()
	else:
		# If requests method is successful, communicate it
		print "Connected!"
		print "  Successfully updated incident!"