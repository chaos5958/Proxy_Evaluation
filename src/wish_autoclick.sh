# !/bin/bash

#Set itertion number
echo Enter iteration number: 
read iter

#Exeucte logcat background process
nohup sh wish_logcat.sh & 
echo $!
logcat_pid=$!

#Auto-clik
rm -rf ../resouce/WISH_LOGCAT
for ((i=0; i<$iter; i++))
do 
    echo ====WISH TEST $i ITERATION=======
    adb shell pm clear com.contextlogic.wish
    adb shell monkey -p com.contextlogic.wish -c android.intent.category.LAUNCHER 1
    sleep 5
    adb shell input tap 829 1658
    adb shell input keyevent 61
    adb shell input keyevent 61
    adb shell input text chaos5958@naver.com
    adb shell input keyevent 61
    adb shell input text zizonama5958
    adb shell input keyevent 61
    adb shell input keyevent 66
    sleep 10
    adb shell input tap 358 1057
    sleep 5 
done
adb shell pm clear com.contextlogic.wish 


#Kill logcat background process
echo $logcat_pid
kill $logcat_pid 
