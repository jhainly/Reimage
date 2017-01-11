# Author:	Jeremiah Hainly
# Purpose:	Open ServiceNow ticket to reimage user. This is part of a larger script
#			that verifies the user's identity in Splunk and sends the user an email
#			to notify of a reimage ticket being created.

import sys
import os
import re
import splunklib.client as client
import splunklib.results as results
from time import sleep
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

########################## Method 1 ###################################
# Search splunk for the inputted user and return their name and email #
#######################################################################
def search(reimageUser):
	#Connect to Splunk Server
	print "\nConnecting to Splunk..."
	try:
		# Connect to Splunk
		service = client.connect(
			# Connection parameters
			host=parser.get('splunk', 'host'),				# Splunk search head addres
			port=parser.getint('splunk', 'port'),				# Splunk default deployment server port
			username=parser.get('splunk', 'username'),		# Admin profile username
			password=parser.get('splunk', 'password'))		# Admin profile password
	except Exception as e:
		print str(e)
		print "\nError connecting to Splunk Server. Please check credentials and URL"
		sys.exit()

	# Positive feedback after connection established
	print "Connected!"

	#Search Splunk for target user, return email address, first and last name
	job = service.jobs.create("| inputlookup "+parser.get('splunk', 'lookupFile')+" | search identity="+reimageUser+" | table identity email givenName last")

	while not job.is_done():
		# Wait until search is complete to avoid errors on successful queries
		sleep(.2)
	# Get the results of the query and write into an array
	reader = results.ResultsReader(job.results())
	# Take the values from the array and write to userInfo
	for result in reader:
		userInfo = str(result)

	#Validate that Splunk returned valid results
	try:
		# If userInfo has a value, this will return true, otherwise it will drop into the "except"
		userInfo
	except NameError:
		# If userInfo does not have a value, negative feedback and close the script
		print "\nInvalid User. Check for typos and verify the user is in Active Directory.\nIf you're doing it right, then the "+parser.get('splunk', 'lookupFile')+" Splunk lookup is broken."
		sys.exit()

	# Parse out and display the data collected from Splunk
	print "Here's what I found:"

	# Parse and print User ID
	getUserID = re.search('(?<=identity\W\W\W\W)\w+', userInfo)
	userID = str(getUserID.group(0))
	print "  User ID: " + userID

	# Parse and print Email
	getUserEmail = re.search('(?<=email\W\W\W\W)\w+\W+\w+\W+\w+', userInfo)
	userEmail = str(getUserEmail.group(0))
	print "  User Email: " + userEmail

	# Parse and print first name
	getFirstName = re.search('(?<=givenName\W\W\W\W)\w+', userInfo)
	firstName = str(getFirstName.group(0))
	print "  User First Name: " + firstName

	# Parse and print last name
	getLastName = re.search('(?<=last\W\W\W\W)\w+', userInfo)
	lastName = str(getLastName.group(0))
	print "  Last Name: " + lastName

	# Return User ID, email, and name for user in original method parameter
	return userID, userEmail, firstName, lastName