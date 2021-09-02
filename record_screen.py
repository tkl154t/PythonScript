import cv2
import numpy as np
import pyautogui
from win32api import GetSystemMetrics

screen_width = GetSystemMetrics(0)
screen_height = GetSystemMetrics(1)

# display screen resolution, get it from your OS settings
SCREEN_SIZE = (screen_width, screen_height)

# define the codec
fourcc = cv2.VideoWriter_fourcc(*"XVID")

# create the video write object
out = cv2.VideoWriter("output.avi", fourcc, 20.0, SCREEN_SIZE)

for i in range(200):
    # make a screenshot
    img = pyautogui.screenshot()

    # convert these pixels to a proper numpy array to work with OpenCV
    frame = np.array(img)

    # convert colors from BGR to RGB
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    # write the frame
    out.write(frame)

    # show the frame
    # cv2.imshow("screenshot", frame)

    # if the user clicks q, it exits
    if cv2.waitKey(1) == ord("q"):
        break

# make sure everything is closed when exited
cv2.destroyAllWindows()
out.release()