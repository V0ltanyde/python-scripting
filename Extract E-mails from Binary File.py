'''
Using Regular Expressions to Find e-mails

'''
#Craig Suhrke
#Assignment 7 v1
#09/26/2024

import sys
import re
from binascii import hexlify 
from prettytable import PrettyTable


# File Chunk Size
CHUNK_SIZE =  4096

# regular expressions

ePatt = re.compile(b'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}')  
uPatt = re.compile(b'\w+:\/\/[\w@][\w.:@]+\/?[\w.\.?=%&=\-@$,]*')

# Create empty lists
emailDict = {}
urlDict = {}

# Read in the binary file test.bin
with open("memdump.bin", 'rb') as binaryFile:
    while True:
        chunk = binaryFile.read(CHUNK_SIZE)
        if chunk:
            emails = ePatt.findall(chunk)
            
            for eachEmail in emails:
                eachEmail = eachEmail.lower()
                try:
                    value = emailDict[eachEmail]
                    value += 1
                    emailDict[eachEmail] = value
                except:
                    emailDict[eachEmail] = 1
        if chunk:
            uRLs = uPatt.findall(chunk)
            
            for eachURL in uRLs:
                eachURL = eachURL.lower()
                try:
                    value = emailDict[eachURL]
                    value += 1
                    urlDict[eachURL] = value
                except:
                    urlDict[eachURL] = 1
        else:
            break
        
emailTable = PrettyTable(['Occurrences','E-Mail Address'])
urlTable = PrettyTable(['Occurrences', 'URL'])

for key, value in emailDict.items():
    emailTable.add_row([value, key.decode("ascii", "ignore")])

for key, value in urlDict.items():
    urlTable.add_row([value, key.decode("ascii", "ignore")])
    
print("EMAILS: Sorted by occurrence")
emailTable.align = "l" 
print(emailTable.get_string(sortby="Occurrences", reversesort=True))
print("\n\n")

print("URLs: Sorted by occurrence")
urlTable.align = "l" 
print(urlTable.get_string(sortby="Occurrences", reversesort=True))
print("\n\n")

