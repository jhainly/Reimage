# Author:  Jeremiah Hainly
# Purpose: Submit host for reimage via ServiceNow, send them an email, and quarantine the host in SEPM

import sys
import time
import splunkReimage
import servicenowReimage
import emailReimage
import sepReimage

def main():
	userOption = input("Welcome to the Reimage Script! What would you like to do?\n\n1) Quarantine, Open Ticket, Send Email\n2) Quarantine, UPDATE Ticket, Send Email\n3) Quarantine ONLY\n4) Remove Quarantine ONLY\n5) Reformat Flash Drive\n\nPick a number: ")

	if userOption == 1:
		sepCommand = "Quarantine"
		hostname = raw_input("Target hostname?: ")
		reimageUser = raw_input("Target user ID?: ")
		mssTicket = raw_input("MSS Ticket Number?: ")
		userID, userEmail, firstName, lastName = splunkReimage.search(reimageUser)
		snTicket = servicenowReimage.submit(hostname, reimageUser)
		emailReimage.reimage(hostname, firstName, userEmail, mssTicket, snTicket)
		sepReimage.reimage(hostname, sepCommand)
	elif userOption == 2:
		sepCommand = "Quarantine"
		snTicket = raw_input("ServiceNow Ticket Number? (Number only): ")
		hostname = raw_input("Target hostname?: ")
		reimageUser = raw_input("Target user ID?: ")
		mssTicket = raw_input("MSS Ticket Number?: ")
		userID, userEmail, firstName, lastName = splunkReimage.search(reimageUser)
		sysID = servicenowReimage.request(snTicket)
		servicenowReimage.update(sysID, hostname, reimageUser)
		emailReimage.reimage(hostname, firstName, userEmail, mssTicket, snTicket)
		sepReimage.reimage(hostname, sepCommand)
	elif userOption == 3:
		sepCommand = "Quarantine"
		hostname = raw_input("Target hostname?: ")
		sepReimage.reimage(hostname, sepCommand)
	elif userOption == 4:
		sepCommand = "Undo"
		hostname = raw_input("Target hostname?: ")
		sepReimage.reimage(hostname, sepCommand)
	elif userOption == 5:
		hostname = raw_input("Target hostname?: ")
		reimageUser = raw_input("Target user ID?: ")
		mssTicket = raw_input("MSS Ticket Number?: ")
		userID, userEmail, firstName, lastName = splunkReimage.search(reimageUser)
		emailReimage.reformat(hostname, firstName, userEmail, mssTicket)
	else:
		print "Invalid input."
		sys.quit()
main()