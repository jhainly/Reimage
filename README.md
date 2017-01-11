## Synopsis

Reimage is a python script that provides information technologists with a template for automating a task between **Splunk**, **ServiceNow**, **Symantec Endpoint Protection (SEP)**, and **email**.

## Getting Started

Change the configs.template file contents to match your environment. Then, rename the file to configs.ini.

Either run the raw python or use pyinstaller on the provided spec file to compile into an executable.

```
pyinstaller.exe --onefile Reimage.spec
```

## Code Example
```
C:\Users\Me\Downloads>Reimage.exe
Welcome to the Reimage Script! What would you like to do?

1) Quarantine, Open Ticket, Send Email
2) Quarantine, UPDATE Ticket, Send Email
3) Quarantine ONLY
4) Remove Quarantine ONLY
5) Reformat Flash Drive

Pick a number:
```
## Motivation

The use case in this script is an information security team that identifies a computer that requires a reimage. This script automates the normally manual process to lookup user information in **Splunk**, quarantine the affected computer in **SEP**, submit a ticket to their client support to request a reimage in **ServiceNow**, and send an **email** to the owner of the computer.

## About the Author

Jeremiah Hainly: https://www.linkedin.com/in/jeremiahhainly

## Special Thanks

Brian Nafziger: https://www.linkedin.com/in/bnafziger
