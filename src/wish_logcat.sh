# !/bin/bash

adb logcat -c
adb logcat | grep --line-buffered EXTRACTOCOL > ../resouce/WISH_LOGCAT


