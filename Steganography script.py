from PIL import Image  # pip install pillow

# Pixel tuple index
RED = 0
GREEN = 1
BLUE = 2

# Obtain the Basic image information
try:
    img = Image.open('monalisa.bmp')
    pix = img.load()

    # Define the hideDict properly
    hideDict = {
        'deadDrop': [0, 0, 0],
        'dropIntersection': [0, 0, 1],
        'dropLocation': [0, 1, 1],
        'dropTime': [1, 1, 0],
        'dropAbort': [1, 1, 1]
    }

    # Only modify the first row (r = 0) and first 5 pixels (c = 0 to 4)
    r = 0
    for c, (key, value) in zip(range(5), hideDict.items()):
        # Read the Pixel
        pixel = pix[c, r]
        redPx, grnPx, bluPx = pixel[RED], pixel[GREEN], pixel[BLUE]

        # Print the Current Value of the Pixel
        print("\nOriginal Pixel at ({},{}):".format(c, r))
        print("RED: ", '{:08b}'.format(redPx))
        print("GRN: ", '{:08b}'.format(grnPx))
        print("BLU: ", '{:08b}'.format(bluPx))

        # Update the last bit of each color based on hideDict values
        redPx = (redPx & 0b11111110) | value[0]
        grnPx = (grnPx & 0b11111110) | value[1]
        bluPx = (bluPx & 0b11111110) | value[2]

        # Print the New Value of the Altered Pixel after modifications
        print("\nAltered Pixel at ({},{}):".format(c, r))
        print("RED: ", '{:08b}'.format(redPx))
        print("GRN: ", '{:08b}'.format(grnPx))
        print("BLU: ", '{:08b}'.format(bluPx))

        # Update the pixel
        pix[c, r] = (redPx, grnPx, bluPx)

    # Save this as a new image
    img.save('monaLisaTest.bmp')
    print("\nPixel Steganography Done")

except Exception as err:
    print("Steg Failed: ", str(err))
