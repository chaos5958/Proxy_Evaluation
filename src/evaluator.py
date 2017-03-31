''' Created on 2016. 7. 17.

@author: Hyun Ho
'''
from __future__ import print_function
import sys
import os
import re
import xlwt
import getopt
import math
from subprocess import call

TSHARK_SEPARATOR = "$"
TSHARK_SEPARATOR_NUM= 5
TSHARK_SEPARATOR_PATTERN = "[%s]{%d}" % (TSHARK_SEPARATOR, TSHARK_SEPARATOR_NUM)
LOG_LINE_RE = re.compile(r"(\S+) (\S+) (\S+) (\S+)$")
#TCPDUMP_LINE_RE = re.compile(r"\S+ \S+ \S+ (\d+)[:](\d+)[:](\d+)[.](\d+) \S+[\t](\d*)[\t](\S*)[\t](\S*)[\t]([\S|\s]*)[\t](\S*)[\t](\S*)[\t](\S*)[\t](\S*)[\t](\S*)[\t](\S*)[\t](\S*)")
TCPDUMP_LINE_RE = re.compile(r"\S+ \S+ \S+ (\d+)[:](\d+)[:](\d+)[.](\d+) \S+{0}(\d*){0}(\S*){0}(\S*){0}([\S|\s]*){0}(\S*){0}(\S*){0}(\S*){0}(\S*){0}(\S*){0}(\S*){0}(\S*)".format(TSHARK_SEPARATOR_PATTERN))

TSHARK_DUMP_FILE = "../resource/tshark_dumpfile"
TSHARK_PREPROCESS_FILE = "../resource/tshark_ppfile"
SSL_KEY_FILE = None
TCPDUMP_FILE = None
SSL_APP_CONENT_NUM = 23

class LogManager:
    def __init__(self):
        self.request_list = []
        self.response_list = []
        self.flow_list = []

    def addLogInfo(self, url, time):
        if len(self.loglist) != 0:
            isdone = False
            for log in self.loglist:
                if log.url == url:
                    log.num = log.num + 1
                    log.time = log.time + time
                    isdone = True

            if isdone == False:
                newlog = LogUnit(url, time)
                self.loglist.append(newlog)
        else:
            newlog = LogUnit(url, time)
            self.loglist.append(newlog)

    def getExcelResult(self, save_file = "default_log.xls"):
        book = xlwt.Workbook(encoding="utf-8")

        sheet1 = book.add_sheet("sheet1")
        sheet1.write(0, 0, "request")
        sheet1.write(0, 1, "lantency")

        index_row = 1
        for flow in self.flow_list:
            sheet1.write(index_row, 0, flow.request.method + " " + flow.request.http_host + flow.request.uri)
            sheet1.write(index_row, 1, flow.latency())
            index_row = index_row + 1

        book.save(save_file)

    def callTshark(self, filter = None):
        global TSHARK_SEPARATOR
        global TSHARK_SEPARATOR_NUM
        global TSHARK_DUMP_FILE
        global TSHARK_PREPROCESS_FILE

        call(self.getTsharkCommand(filter), shell=True)

        fi = open(TSHARK_DUMP_FILE, 'r')
        fo = open(TSHARK_PREPROCESS_FILE, 'w')
        for line in fi:
            line = line.replace('\t', TSHARK_SEPARATOR *TSHARK_SEPARATOR_NUM)
            fo.write(line)
        fi.close()

    def getReqRespfromDump(self):
        global TSHARK_DUMP_FILE
        global TCPDUMP_FILE
        global SSL_KEY_FILE
        global TSHARK_SEPARATOR
        global TSHARK_SEPARATOR_NUM
        global TSHARK_PREPROCESS_FILE

        self.callTshark()

        fi = open(TSHARK_PREPROCESS_FILE, 'r')
        for line in fi:
            match = TCPDUMP_LINE_RE.match(line.strip())
            if match is not None:
                hour, minute, second, second_specific, tcp_stream, request_method, request_uri, response_phrase, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, ssl_content_type, http_host = match.groups()
                time_sec = int(hour) * 3600 + int(minute) * 60 + int(second) + int(second_specific) * pow(10, -9)
                if tcp_stream != "":
                    if request_method != "":
                        request_new = HttpRequest(int(tcp_stream), request_method, request_uri, time_sec, ip_src, ip_dst, int(tcp_srcport), int(tcp_dstport), int(frame_number), http_host)
                        self.request_list.append(request_new)
                    if response_phrase != "":
                        response_new = HttpResponse(int(tcp_stream), response_phrase, time_sec, ip_src, ip_dst, int(tcp_srcport), int(tcp_dstport), int(frame_number), ssl_content_type)
                        self.response_list.append(response_new)
            else:
                print("tshark file format should be modified")
                #print(line)
        fi.close()

    def pairReqResp(self):
        for req in self.request_list:
            ismatched = False
            for res in self.response_list:
                if self.isSameFlow(req, res) == True and res.ismatched == False:
                    res.ismatched = True
                    flow_new = HttpFlow(req, res)
                    self.flow_list.append(flow_new)
                    ismatched = True
                    break
            if ismatched == False:
                self.applyHuersticforStream(req)

    #Handle tcp_stream which wireshark failed to reassemble
    def applyHuersticforStream(self, httprequest):
        global TCPDUMP_FILE
        global SSL_KEY_FILE
        global TSHARK_DUMP_FILE
        global SSL_APP_CONENT_NUM
        global TSHARK_PREPROCESS_FILE

        httpresponse = None

        self.callTshark("tcp.stream == %d" % (httprequest.tcp_stream))

        fi = open(TSHARK_PREPROCESS_FILE, 'r')
        for line in fi:
            match = TCPDUMP_LINE_RE.match(line.strip())
            if match is not None:
                hour, minute, second, second_specific, tcp_stream, request_method, request_uri, response_phrase, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, ssl_content_type, http_host = match.groups()
                time_sec = int(hour) * 3600 + int(minute) * 60 + int(second) + int(second_specific) * pow(10,-9)
                if self.isSameFlowHueristic(httprequest, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, ssl_content_type, response_phrase):
                    httpresponse = HttpResponse(int(tcp_stream), None, time_sec, ip_src, ip_dst, int(tcp_srcport), int(tcp_dstport), int(frame_number), ssl_content_type)

                if httprequest.method is not None and time_sec > httprequest.time:
                    break

        if httpresponse is not None:
            httpflow_new = HttpFlow(httprequest, httpresponse)
            self.flow_list.append(httpflow_new)
        else:
            print("request has no reponse pair: " + str(httprequest))

        fi.close()

    def getTsharkCommand(self, option = None):
        global TCPDUMP_FILE
        global SSL_KEY_FILE
        global TSHARK_DUMP_FILE
        global SSL_APP_CONENT_NUM

        if option is not None:
            return "tshark -nr %s -o ssl.keylog_file:%s -Y '%s' -T fields -e frame.time -e tcp.stream -e http.request.method -e http.request.uri -e http.response.phrase -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.number -e ssl.record.content_type -e http.host> %s" % (TCPDUMP_FILE, SSL_KEY_FILE, option, TSHARK_DUMP_FILE)
        else:
            return "tshark -nr %s -o ssl.keylog_file:%s -T fields -e frame.time -e tcp.stream -e http.request.method -e http.request.uri -e http.response.phrase -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.number -e ssl.record.content_type -e http.host > %s" % (TCPDUMP_FILE, SSL_KEY_FILE, TSHARK_DUMP_FILE)

    def isSameFlow(self, httprequest, httpresponse):
        if httprequest.tcp_stream != httpresponse.tcp_stream:
            return False

        if httprequest.ip_src != httpresponse.ip_dst:
            return False

        if httprequest.ip_dst != httpresponse.ip_src:
            return False

        if httprequest.tcp_srcport != httpresponse.tcp_dstport:
            return False

        if httprequest.tcp_dstport != httpresponse.tcp_srcport:
            return False

        return True

    def isSameFlowHueristic(self, httprequest, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, ssl_content_type, response_phrase):
        global SSL_APP_CONENT_NUM

        if ip_src is None or tcp_srcport is None or frame_number is None or ssl_content_type is None:
            return False

        type_list = ssl_content_type.split(',')

        if SSL_APP_CONENT_NUM in type_list:
            return False

        if httprequest.ip_src != ip_dst:
            return False

        if httprequest.ip_dst != ip_src:
            return False

        if httprequest.tcp_srcport != int(tcp_dstport):
            return False

        if httprequest.tcp_dstport != int(tcp_srcport):
            return False

        if response_phrase is not None:
            return False

        return True

    def printRequest(self):
        for req in self.request_list:
            print(req)

    def printResponse(self):
        for res in self.response_list:
            print(res)

    def printFlow(self):
        for flow in self.flow_list:
            print(flow)

class HttpRequest:
    def __init__(self, tcp_stream, method, uri, time, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, http_host):
        self.tcp_stream = tcp_stream
        self.method = method
        self.uri = uri
        self.time = time
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.tcp_srcport = tcp_srcport
        self.tcp_dstport = tcp_dstport
        self.frame_number = frame_number
        self.http_host = http_host

    def __str__(self):
        return "HttpRequest tcp.stream: %d http.method: %s http.host: %s http.uri: %s time: %f ip_src: %s ip_dst: %s tcp_srcport: %d tcp_dstport: %d frame_number: %d" % (self.tcp_stream, self.method, self.http_host, self.uri, self.time, self.ip_src, self.ip_dst, self.tcp_srcport, self.tcp_dstport, self.frame_number)

class HttpResponse:
    def __init__(self, tcp_stream, phrase, time, ip_src, ip_dst, tcp_srcport, tcp_dstport, frame_number, ssl_content_type):
        self.tcp_stream = tcp_stream
        self.phrase = phrase
        self.time = time
        self.ismatched = False
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.tcp_srcport = tcp_srcport
        self.tcp_dstport = tcp_dstport
        self.frame_number = frame_number
        self.ssl_content_type = ssl_content_type

    def __str__(self):
        return "HttpResponse tcp.stream: %d http.phrase: %s time: %f ip_src: %s ip_dst: %s tcp_srcport: %d tcp_dstport: %d frame_number: %d ssl_content_type: %s" % (self.tcp_stream, self.phrase, self.time, self.ip_src, self.ip_dst, self.tcp_srcport, self.tcp_dstport, self.frame_number, self.ssl_content_type)

class HttpFlow:
    def __init__(self, request, response):
        self.request = request
        self.response = response

    def latency(self):
        return self.response.time - self.request.time

    def __str__(self):
        return str(self.request) + os.sep + str(self.response) + os.linesep + "Latency" + str(self.latency())


class LogUnit:
    def __init__(self, url, time):
        self.url = url
        self.time = time
        self.num = 1


def analysis_dump(input_file, output_file):
    logManager_ = LogManager()
    fi = open(input_file, 'r')

    for line in fi:
        match = LOG_LINE_RE.match(line.strip())
        if match is not None:
            key_01, value_01, key_02, value_02 = match.groups()
            if key_01 == "URL" and  key_02 == "TIME":
                logManager_.addLogInfo(value_01.strip(), int(value_02))
            else:
                print ("%s is an unappropriate dump file" % (input_file))

        else:
            print ("%s is an unappropriate dump file" % (input_file))

    logManager_.getExcelResult(output_file)

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

def main():
    global TCPDUMP_FILE
    global SSL_KEY_FILE

    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:s:")
    except getopt.GetoptError:
        print("python -d <dump_file> -s <ssl_key_file>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-d":
            TCPDUMP_FILE = arg
        elif opt == "-s":
            SSL_KEY_FILE = arg
        else:
            print("python -d <dump file> -s <ssl_key_file>")
            sys.exit(2)

    if (TCPDUMP_FILE is None) or (SSL_KEY_FILE is None):
        print("python -d <dump file> -s <ssl_key_file>")
        sys.exit(2)

    logger = LogManager()
    logger.getReqRespfromDump()
    logger.pairReqResp()
    #logger.printRequest()
    #logger.printResponse()
    logger.printFlow()
    logger.getExcelResult()

if __name__ == '__main__':
    main()
    #parse_logcat("../resource/WISH_LOGCAT", "../resource/WISH_RESULT_LOGCAT")
    #parse_dump("../resource/WISH_RESULT_DUMP")
    #analysis_dump("../resource/WISH_RESULT_DUMP", "../result/WISH_DUMP_LOG.xls")
    #analysis_dump("../resource/WISH_RESULT_LOGCAT", "../result/WISH_LOGCAT_LOG.xls")











