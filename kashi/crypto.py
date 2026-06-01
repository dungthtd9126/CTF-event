import cv2
import numpy as np
from skimage import color, restoration
import matplotlib.pyplot as plt

# Load the blurred image in grayscale
img = color.rgb2gray(cv2.imread('challenge.png'))

# Guess the Point Spread Function (e.g., a simple 5x5 box blur kernel)
# You usually have to brute-force the size to match the author's blur
kernel_size = 5
psf = np.ones((kernel_size, kernel_size)) / (kernel_size * kernel_size)

# Apply Wiener deconvolution
deconvolved = restoration.wiener(img, psf, balance=0.01)

# Display the result
plt.imshow(deconvolved, cmap='gray')
plt.show()