# Author:  Jeremiah Hainly
# Purpose: Send emails to users to notify them of a reimage. This is part of a larger script
#          that verifies the user's identity in Splunk and sends the user an email
#          to notify of a reimage ticket being created.

######## Imports ##########
# Import required modules #
###########################
import smtplib
import sys
import os
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEImage import MIMEImage
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

################ METHOD 1 ################################
# Send email to user to reformat an infected flash drive #
##########################################################
def reformat(targetHost, targetFirst, targetEmail, mssNumber):
	print "\nConnecting to " + parser.get('email', 'smtp')
	try:
		# Set email from, to, cc
		strFrom = parser.get('email', 'groupEmail')
		strTo = targetEmail
		#strCc = parser.get('email', 'testEmail')	# TEST
		strCc = parser.get('email', 'groupEmail')	# PRODUCTION

		# Create the root message and fill in the from, to, and subject headers      
		msgRoot = MIMEMultipart('related')
		msgRoot['Subject'] = 'Flash Drive Reformat'
		msgRoot['From'] = strFrom
		msgRoot['To'] = strTo
		msgRoot['Cc'] = strCc
		msgRoot.preamble = 'This is a multi-part message in MIME format.'

		# Encapsulate the plain and HTML versions of the message body in an
		# 'alternative' part, so message agents can decide which they want to display.
		msgAlternative = MIMEMultipart('alternative')
		msgRoot.attach(msgAlternative)

		msgText = MIMEText('This is the alternative plain text message. Error with HTML version')
		msgAlternative.attach(msgText)

		# Reference the image in the IMG SRC attribute by the ID we give it below
		msgText = MIMEText("""\
			<!doctype html5>
			<html>
			<body>
				<p>Hi """ + targetFirst + """,</p>
				<p>""" + parser.get('email','teamName') + """ has identified that a flash drive with malicious files was plugged into your Hershey computer with the hostname: """ + targetHost + """. Symantec blocked the files from copying to your computer, but did not clean the flash drive.</p>
				<p>We recommend formatting your flash drive, which will erase ALL files (including hidden files) from the drive. You can format your flash drive by following these steps:</p>
				<ul>
					<li>Click "Start" > "Computer"</li>
					<li>Right click on flash drive</li>
					<li>Click "Format..."</li>
					<li>File system: NTFS</li>
					<li>Click "Start"</li>
				</ul>
				<p>Thank you for your cooperation and understanding as we work to keep yours and the company's information private and secure. If you have any questions, please reach out to """ + parser.get('email', 'groupEmail') + """. Please reference MSS Incident ID #""" + mssNumber + """.</p>
				<p>Thank you,</p>
				<img src="cid:image1">
			</body>
			</html>
			""", 'html')
		msgAlternative.attach(msgText)

		# This example assumes the image is in the current directory
		fp = open(resource_path('smallCD.png'), 'rb')
		msgImage = MIMEImage(fp.read())
		fp.close()

		# Define the image's ID as referenced above
		msgImage.add_header('Content-ID', '<image1>')
		msgRoot.attach(msgImage)

		# Send the email (assumes SMTP authentication is not required)
		import smtplib
		smtp = smtplib.SMTP()
		smtp.connect(parser.get('email', 'smtp'))
		smtp.sendmail(strFrom, [strTo,strCc], msgRoot.as_string())
		smtp.quit()
	except:
		print "  Error sending mail"
		print sys.exc_info()[0]
		sys.exit()

	print "Connected!"
	print "  Sent email to " + targetEmail

################ METHOD 2 ###################
# Send email to user to notify of a reimage #
#############################################
def reimage(targetHost, targetFirst, targetEmail, mssNumber, snNumber):
	print "\nConnecting to " + parser.get('email', 'smtp')
	try:
		# Set email from, to, cc
		strFrom = parser.get('email', 'groupEmail')
		strTo = targetEmail
		#strCc = parser.get('email', 'testEmail')	# TEST
		strCc = parser.get('email', 'groupEmail')	# PRODUCTION

		# Create the root message and fill in the from, to, and subject headers
		msgRoot = MIMEMultipart('related')
		msgRoot['Subject'] = 'Workstation Quarantined: '+ targetHost
		msgRoot['From'] = strFrom
		msgRoot['To'] = strTo
		msgRoot['Cc'] = strCc
		msgRoot.preamble = 'This is a multi-part message in MIME format.'

		# Encapsulate the plain and HTML versions of the message body in an
		# 'alternative' part, so message agents can decide which they want to display.
		msgAlternative = MIMEMultipart('alternative')
		msgRoot.attach(msgAlternative)

		# If the script can't send the HTML, it will send this
		msgText = MIMEText('This is the alternative plain text message. Error with HTML version')
		msgAlternative.attach(msgText)

		# Email text
		# Reference the image in the IMG SRC attribute by the ID we give it below
		msgText = MIMEText("""\
			<!doctype html5>
			<html>
			<body>
				<p>Hi """ + targetFirst + """,</p>
				<p>""" + parser.get('email','teamName') + """ has identified your workstation with the hostname, """ + targetHost + """, as an infected workstation. A ticket (INC"""+snNumber+""") has been generated to your local client support team to reimage the infected workstation. The workstation will be quarantined from the Hershey internal network within the next hour and will not be allowed back on the network until the system has been verified as reimaged.</p>
				<p>Please review the security awareness training available at """ + parser.get('email', 'trainingSite') + """. Thank you for your cooperation and understanding as we work to keep yours and the company's information private and secure.</p>
				<p>If you have any questions, please reach out to """ + parser.get('email', 'groupEmail') + """. Please reference incident number """ + mssNumber + """.</p>
				<p>Thank you,</p>
				<img src="cid:image1">
			</body>
			</html>
			""", 'html')
		msgAlternative.attach(msgText)

		# This example assumes the image is in the current directory
		fp = open(resource_path(parser.get('email', 'teamLogo')), 'rb')
		msgImage = MIMEImage(fp.read())
		fp.close()

		# Define the image's ID as referenced above
		msgImage.add_header('Content-ID', '<image1>')
		msgRoot.attach(msgImage)

		# Send the email (assumes SMTP authentication is not required)
		import smtplib
		smtp = smtplib.SMTP()
		smtp.connect(parser.get('email','smtp'))
		smtp.sendmail(strFrom, [strTo,strCc], msgRoot.as_string())
		smtp.quit()
	except:
		print "  Error sending mail"
		print sys.exc_info()[0]
		sys.exit()

	print "Connected!"
	print "  Sent email to " + targetEmail
  
#sendmail(hostname, firstName, userEmail, mssTicket, snTicket)