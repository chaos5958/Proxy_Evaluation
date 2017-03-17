'''
Created on 2016. 7. 17.

@author: Hyun Ho
'''
from __future__ import print_function
import sys
from subprocess import call


def compare_dump_logcat():
    #TODO

def parse_logcat(input_file, output_file):
    fi = open(input_file, 'r')
    fo = open(output_file, 'w')

    for line in fi:
        line_elem = line.split()
        key_idx = line_elem.index("$EXTRACTOCOL$")
        print("URL", line_elem[key_idx + 5], "TIME", line_elem[key_idx + 4], file=fo)

def parse_dump(output_file):
    #call(["mitmdump", "-q", "-n", "-s", "extract_info_from_dump.py", "-r", "../resource/WISH_DUMP"])
    call("mitmdump -q -n -s extract_info_from_flow.py -r ../resource/WISH_DUMP > " + output_file, shell=True)

if __name__ == '__main__':
    #parse_logcat("../resource/WISH_LOGCAT", "../resource/WISH_RESULT_LOGCAT")
    parse_dump("../resource/WISH_RESULT_DUMP")











