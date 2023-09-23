'''
Extract file Metadata and Hash
Craig Suhrke
09/11/2023
Version 2.0
'''

import os        # Python standard library os/file system methods
import hashlib   # Python standard library hashlib
import sys       # Python standard library system specifics and functions
import time

from prettytable import PrettyTable

print("Second Script: Obtain File Meta Data and Hash\n")

while True:
    targetFolder = input("Please enter a directory path: ")
    if os.path.isdir(targetFolder):
        break
    else:
        print("\nInvalid Folder ... Please Try Again")


print("\nAccessing Metadata for : ", targetFolder)                  
    
tbl = PrettyTable(['AbsPath','FileSize','LastAccessed','LastModified','CreatedTime','SHA-256 HASH'])    

def GetFileMetaData(fileName):

    try:
        
        metaData = os.stat(fileName)
        fileSize = metaData.st_size
        timeLastAccess = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_atime))
        timeLastModified = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_mtime))
        timeCreated = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_ctime))
        
      
        return True, None, fileSize, timeLastAccess, timeLastModified, timeCreated
    
    except Exception as err:
        return False, str(err), None, None
    
for currentRoot, dirList, fileList, in os.walk(targetFolder):
    
    for nextFile in fileList:
        fullPath = os.path.join(currentRoot, nextFile)
        absPath = os.path.abspath(fullPath)
        success, errInfo, fileSize, timeLastAccess, timeLastModified, timeCreated = GetFileMetaData(fullPath)
        try:
            
            with open(absPath, 'rb') as target:
            
                fileContents = target.read()
                sha512Obj = hashlib.sha512()
                sha512Obj.update(fileContents)
                hexDigest = sha512Obj.hexdigest()    
        
        except Exception as err:
            sys.exit("\nException: "+str(err))
        
        
        tbl.add_row( [ absPath, fileSize, timeLastAccess, timeLastModified, timeCreated, hexDigest ] )

tbl.align = "l"

print(tbl.get_string(sortby="FileSize", reversesort = True))

print("\nScript Done")
    