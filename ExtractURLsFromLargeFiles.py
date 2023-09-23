'''
Script: Week 4 Search
Craig Suhrke
09/18/2023
'''
''' IMPORT LIBARARIES'''
import sys
import os
import re
from prettytable import PrettyTable

'''SET PSEUDO CONSTANTS'''

urlPattern = re.compile(b'\w+:\/\/[\w@][\w.:@]+\/?[\w\.?=%&=\-@/$,]*')
chunkSize = 65535
inputFile = "mem.raw"

if __name__ == '__main__':

    print("\nSimple File Search for URLs")
    
      
    try:
        
        urlDict = {}  # Create a dictionary to keep track of the hits
        
         
     
        if os.path.isfile(inputFile):  # Verify file is real
            with open(inputFile, 'rb') as targetFile:
                while True:          
                    fileChunk = targetFile.read(chunkSize)
                    fileChunk = fileChunk.lower()  # broaden search
        
                    if fileChunk:  # if we still have data
                        # Search this chunk for our keyword
                        urlMatches = urlPattern.findall(fileChunk)
                        print(urlMatches)
                        for urlMatches in fileChunk:
                            
                            cnt = urlDict[urlMatches]
                            urlDict[urlMatches] = cnt + 1
                    else:
                        # File has been processed
                        # Set up PrettyTable
                        tbl = PrettyTable(['OCCURS','URL'])
                        for count, url in urlDict.items():
                            tbl.add_row([cnt, url])
                        tbl.align = 'l'
                        print(tbl.get_string(sortby="OCCURS", reversesort=True))
                        print(tbl.get_json_string())
                        code = tbl.get_html_string()
                        html_file = open('Table.html', 'w')
                        tml_file = html_file.write(code)                            
                        
        else:
            print(largeFile, "is not a valid file")
            sys.exit("Script Aborted")
                        
    except Exception as err:
        sys.exit("\nException: "+str(err)+ "Script Aborted")
       
           
print("\nFile Processed ... Script End")