'''
Rainbow Tables
Craig Suhrke
09-22-2023
'''

import os
import itertools
import hashlib
import pickle

rainbowTable = {}

print("Create Simple Rainbow Table")
for variations in range(4,8):
    for pwTuple in itertools.product("abc123&", repeat=variations):
        pw = ""
        md5Hash = hashlib.md5()
        for eachChr in pwTuple:
            pw = pw+"".join(eachChr)
        pw = bytes(pw, 'ascii')
        md5Hash.update(pw)
        md5Digest = md5Hash.hexdigest()
        rainbowTable[md5Digest] = pw

#print("Rainbow Size: ", len(rainbowTable), "\n")
#for hashValue, pwValue in rainbowTable.items():
    #print(hashValue, pwValue)
    
pickleFileWrite = open('./rainbowTable.db', 'wb')
#Create any python object

pickle.dump(rainbowTable, pickleFileWrite)                      
pickleFileWrite.close() 

# Open the pickle file (read binary)
pickleFileRead = open('./rainbowTable.db', 'rb')

# LOAD the serialized data into a list + print
print("\nLoading the pickled list\n")
retrievedList = pickle.load(pickleFileRead)


entryList = list(rainbowTable.items())   # Next convert the dictionary to a list


# Display the recovered List
print("First-Five:\n",entryList[:5])
print("Last-Five:\n",entryList[-5:])

pickleFileRead.close()

print("\nEnd Sample script")
