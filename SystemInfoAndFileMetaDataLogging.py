'''
Logging script with MetaData
CYBV 312
Craig Suhrke
09/27/2023
'''

# Python Standard Libaries 
import os
import re
import logging
import platform
import socket
import time
import uuid
import hashlib

import psutil  # pip install psutil

def getSystemInfo():
    try:
        info={}
        info['platform']=platform.system()
        info['platform-release']=platform.release()
        info['platform-version']=platform.version()
        info['architecture']=platform.machine()
        info['hostname']=socket.gethostname()
        info['ip-address']=socket.gethostbyname(socket.gethostname())
        info['mac-address']=':'.join(re.findall('..', '%012x' % uuid.getnode()))
        info['processor']=platform.processor()
        info['ram']=str(round(psutil.virtual_memory().total / (1024.0 **3)))+" GB"
        return info
    except Exception as e:
        logging.exception(e)
        return False
    
def getFileMetaData(directoryPath):
    print("\nAccessing Metadata for: ", directoryPath)
    fileList = os.listdir(directoryPath)
    metaData = {}
    
    # Loop through each file to get full path and stats
    for eachFile in fileList:
        filePath = os.path.join(directoryPath, eachFile)
        absPath = os.path.abspath(filePath)
        fileStats = os.stat(absPath)  # Calculate metadata for the file

        # Determine if the path is a file and grab specific items from metadata
        if os.path.isfile(absPath):
            fileSize = os.path.getsize(absPath)
            timeLastAccess = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(fileStats.st_atime))
            timeLastModified = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(fileStats.st_mtime))
            timeCreated = time.strftime("%A %d %B %Y %H:%M:%S", time.gmtime(fileStats.st_ctime))
            with open(absPath, 'rb') as target:
            
                fileContents = target.read()
                sha256Obj = hashlib.sha256()
                sha256Obj.update(fileContents)
                hexDigest = sha256Obj.hexdigest()            

            metaData[eachFile] = {
                'File Size': fileSize,
                'Last Access Time': timeLastAccess,
                'Last Modified Time': timeLastModified,
                'Creation Time': timeCreated, 'SHA-256':hexDigest
            }
    return metaData
    
def main():
        
    if os.path.isfile('Suhrke-ScriptLog.txt'):   # REPLACE YOURNAME with Your Name
        os.remove("Suhrke-ScriptLog.txt")
        
        # configure the python logger, Replace YOURNAME
        logging.basicConfig(filename='Suhrke-ScriptLog.txt', level=logging.DEBUG, format='%(process)d-%(levelname)s-%(asctime)s %(message)s')
        logging.info("Script Start\n")
        
        investigator = input("Investigator Name:  ")   # Enter Your Name at this prompt
        organization = input("Class Code:       ")   # Enter the Class at this prompt i.e. CYBV-312 YOUR SECTION
        directoryPath = input("Please enter a directory path: ")
        
        sysInfo = getSystemInfo()
        metaData = getFileMetaData(directoryPath)
        
        if sysInfo:
            logging.info(f'Investigator: {investigator}')
            logging.info(f'Class Code: {organization}')
            logging.info('============================================================================================')
            logging.info('***** System Information ****')
            for key, value in sysInfo.items():
                logging.info(f'{key}: {value}')
            logging.info('============================================================================================')
            logging.info(f'{directoryPath}')
        if metaData:
            logging.info('***** File Metadata ****')
            fileCount = 0
            for filename, data in metaData.items():
                logging.info(f'File: {filename}')
                for key, value in data.items():
                    logging.info(f'{key}: {value}')
                logging.info('===========================================================================================')
                fileCount += 1
        logging.info(f'\n')        
        logging.info(f'Files Processed: {fileCount}')
        logging.info(f'Script End')
               

if __name__ == '__main__':

    print("\n\nWeek-6 Logging Script - Craig Suhrke \n")
    main()
    print("\nScript End")
   
    
               
                     
   
