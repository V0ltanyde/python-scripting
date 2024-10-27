#Craig Suhrke
#Assignment 8 v1
#09/29/2024

import sys
import re
from binascii import hexlify 
from prettytable import PrettyTable
p
CHUNK_SIZE =  32768

wPatt = re.compile(b'[a-zA-Z]{5,12}')

# Create empty lists
wordDict = {}

# Read in the binary file test.bin
with open("memdump.bin", 'rb') as binaryFile:
    while True:
        chunk = binaryFile.read(CHUNK_SIZE)
        if chunk:
            words = wPatt.findall(chunk)
            
            for eachWord in words:
                eachWord = eachWord.lower()
                try:
                    value = wordDict[eachWord]
                    value += 1
                    wordDict[eachWord] = value
                except:
                    wordDict[eachWord] = 1
        else:
            break


wordTable = PrettyTable(['Occurrences','Words'])

for key, value in wordDict.items():
    wordTable.add_row([value, key.decode("ascii", "ignore")])

print("WORDS: Sorted by occurrence")
wordTable.align = "l" 
print(wordTable.get_string(sortby="Occurrences", reversesort=True))
print("\n\n")