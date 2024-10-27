#Craig Suhrke
#Assignment 5 v1
#09/19/2024

from PIL import Image
import os
import pathlib
from prettytable import PrettyTable

class ImageProcessor:
    
   def __init__(self, path):
        self.path = path

        for item in path:
            if not Image.open(path):
                
                self.height = "N/A"
                self.width = "N/A"
                self.mode = "N/A"
                
                return

            else:
                image = Image.open(path)
                imageData = image._getexif()
                self.height = image.height
                self.width = image.width
                self.mode = image.mode
                self.format = image.format
                  
def main():
    filePath = input("Enter the path: ").strip()

    if not os.path.isdir(filePath):
            print("This is not a valid directory")
            return


    fileList = []
    
    for root, dirs, files in os.walk(filePath):
        for file in files:
            fullPath = os.path.join(root, file)
            ext = pathlib.Path(fullPath).suffix
            
            if fullPath.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff')):
                processor = ImageProcessor(fullPath)
                fileType = processor.format
                fileExtenstion = ext
                width = processor.width
                height = processor.height
                mode = processor.mode
            else:
                fileType = pathlib.Path(fullPath).suffix.upper().strip(".")
                fileExtenstion = ext
            
            fileList.append((fullPath, fileExtenstion, fileType, width, height, mode ))
                        
    table = PrettyTable()
    table.field_names = ["File", "Ext", "Format", "Width", "Height", "Mode"]
    table.align = "l"

    for files in fileList:
        table.add_row(files)

    print(table)

if __name__ == "__main__":
    main()