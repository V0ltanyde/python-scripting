'''
Script:  WK-2 Script
Author:  Craig Suhrke
Date:    09/04/2023
Version: 1
Purpose: Extract metadata from a user defined file path
'''

''' IMPORT STANDARD LIBRARIES '''
import os       # File System Methods
import time     # Time Conversion Methods

''' IMPORT 3RD PARTY LIBRARIES '''
from prettytable import PrettyTable

''' DEFINE PSEUDO CONSTANTS '''


''' LOCAL FUNCTIONS '''


''' LOCAL CLASSES '''
# NONE

''' MAIN ENTRY POINT '''

if __name__ == '__main__':
        
    
    print("First Script: Obtain File Meta Data\n")
    
    #Get directory from user   
    directoryPath = input("Please enter a directory path: ")
    
    try:

        print("\nAccessing Metadata for : ", directoryPath)                  
        tbl = PrettyTable(['FilePath','FileSize','Last Accessed','Last Modified','Created'])
        fileList = os.listdir(directoryPath)     
             
        #Loop through each file to get full path and stats
        for eachFile in fileList:
            filePath = os.path.join(directoryPath, eachFile)
            absPath  = os.path.abspath(filePath)
            metaData = os.stat(directoryPath)                   
                     
            #Determine if file is real and grab specific items from metadata
            if os.path.isfile(absPath):
                fileSize = os.path.getsize(absPath)
                timeLastAccess = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_atime))
                timeLastModified = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_mtime))
                timeCreated = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(metaData.st_ctime))                  
                tbl.add_row( [ absPath, fileSize, timeLastAccess, timeLastModified, timeCreated ] )
            
        #Insert data from each file into table
        tbl.align = "l"     
        resultString = tbl.get_string(sortby="FileSize", reversesort=True)
        print(resultString)
       
    #Handle an exceptions and print them to the console    
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
      
    
print("\nEnd of Results")