#!/usr/bin/env python
# encoding: utf-8

from __future__ import print_function

import sys
import subprocess
import traceback
import socket
import struct

from argparse import ArgumentParser

tcCmd = "/sbin/tc"


class Filter:
    def __init__(self, qdiscId, classId, srcIp, srcPort, dstIp, dstPort):
        assert(qdiscId is not None and classId is not None)
        self.qdiscId = qdiscId  # int
        self.classId = classId  # int
        self.srcIp = srcIp      # int, 32 bit in network byte order
        self.dstIp = dstIp      # int, 32 bit in network byte order
        self.srcPort = srcPort  # int, 16 bit (in host byte order ?)
        self.dstPort = dstPort  # int, 16 bit (in host byte order ?)

    def __repr__(self):
        s = "Filter "
        if(self.srcIp is not None):
            s += numIpToString(self.srcIp) + ":"
        else:
            s += "None:"
        if(self.srcPort is not None):
            s += str(self.srcPort) + " -> "
        else:
            s += "None -> "
        if(self.dstIp is not None):
            s += numIpToString(self.dstIp) + ":"
        else:
            s += "None:"
        if(self.dstPort is not None):
            s += str(self.dstPort) + " => "
        else:
            s += "None => "
        return s + "Class {}:{}".format(self.qdiscId, self.classId)


class Class:
    def __init__(self, qdiscId, classId, rate, ceil, burst, cburst):
        self.qdiscId = qdiscId  # int
        self.classId = classId  # int
        self.rate = rate        # int, [bps]
        self.ceil = ceil        # int, [bps]
        self.burst = burst      # int, [byte]
        self.cburst = cburst    # int, [byte]
        self.filters = []
        self.bfifo = None

    def __repr__(self):
        if self.filters:
            s = "Class {}:{} (rate: {}bps, ceil: {}bps, burst: {}byte, cburst: {}byte, bfifo: {:d}b) with filters" \
                .format(self.qdiscId, self.classId, self.rate, self.ceil, self.burst, self.cburst, self.bfifo.limit)
            for f in self.filters:
                s += "\n        {}".format(str(f))
            return s
        else:
            return "Class {}:{} (rate: {}bps, ceil: {}bps, burst: {}byte, cburst: {}byte, bfifo: {:d}b) " \
                   "with no filters" \
                .format(self.qdiscId, self.classId, self.rate, self.ceil, self.burst, self.cburst, self.bfifo.limit)


class Bfifo:
    def __init__(self, qdisc_id, class_id, handle, limit):
        self.qdisc_id = qdisc_id  # int
        self.class_id = class_id  # int
        self.handle = handle      # int
        self.limit = limit        # int [byte]


class ClassTBF:
    def __init__(self, qdiscId, classId, rate, peakrate, burst, latency):
        self.qdiscId = qdiscId    # int
        self.classId = classId    # int
        self.rate = rate          # int, [bps]
        self.peakrate = peakrate  # int, [bps]
        self.burst = burst        # int, [byte]
        self.latency = latency    # int, [ms]
        self.filters = []

    def __repr__(self):
        if self.filters:
            s = "Class {}:{} (rate: {}bps, ceil: {}bps, burst: {}byte, cburst: {}byte) with filters" \
                .format(self.qdiscId, self.classId, self.rate, self.ceil, self.burst, self.cburst)
            for f in self.filters:
                s += "\n        {}".format(str(f))
            return s
        else:
            return "Class {}:{} (rate: {}bps, ceil: {}bps, burst: {}byte, cburst: {}byte) with no filters" \
                .format(self.qdiscId, self.classId, self.rate, self.ceil, self.burst, self.cburst)


class Qdisc:
    def __init__(self, qdiscId):
        self.qdiscId = qdiscId  # int
        self.classes = []
    def __repr__(self):
        if(self.classes):
            s = "Qdisc {}: with classes".format(self.qdiscId)
            for c in self.classes:
                s += "\n    {}".format(str(c))
            return s
        else:
            return "Qdisc {}: with no classes".format(self.qdiscId)


# numIp must be in network byte order
def numIpToString(numIp):
    return socket.inet_ntoa(struct.pack('!L', numIp))

# returns numIp in nework byte order
def stringIpToNum(stringIp):
    return struct.unpack("!L", socket.inet_aton(stringIp))[0]

# returns own IP as string
def getOwnIp(dev):
    ret = subprocess.check_output(["ifconfig", dev])
    ret = ret.splitlines()
    assert(len(ret) > 2 and ret[0].startswith(dev))
    L = ret[1].strip().split()
    assert(L[0] == "inet")
    LL = L[1].split(":")
    assert(LL[0] == "addr")
    ipStr = LL[1]
    return ipStr
    
'''filter parent 1: protocol ip pref 1 u32 fh 800::801 order 2049 key ht 800 bkt 0 flowid 1:11 
       match 01020304/ffffffff at 12
       match 0000005a/0000ffff at 20'''
def parseFilterLines(fl):
    
    # sanity checks
    assert(len(fl) >= 2)
    
    # parse first line
    L = fl[0].split()
    # sanity checks
    assert(len(L) == 19
           and L[0] == "filter" and L[1] == "parent" and L[3] == "protocol" and L[4] == "ip"
           and L[5] == "pref" and L[6] == "1" and L[7] == "u32" and L[8] == "fh" and L[10] == "order"
           and L[12] == "key" and L[13] == "ht" and L[14] == "800" and L[15] == "bkt" and L[16] == "0"
           and L[17] == "flowid")
    # get qdisc ID
    LL = L[2].split(":")
    assert("" == LL[1])
    qdiscId = int(LL[0])
    # get class ID
    LL = L[18].split(":")
    assert(qdiscId == int(LL[0]))
    classId = int(LL[1])
    
    # parse further lines
    srcIp = dstIp = srcPort = dstPort = None
    for _ in fl[1:]:
        L = _.split()
        # sanity checks
        assert(len(L) == 4 and L[0] == "match" and L[2] == "at")
        off = int(L[3])
        LL = L[1].split("/")
        assert(len(LL) == 2)
        val = int(LL[0], 16)
        mask = int(LL[1], 16)
        if(off == 12):
            assert(srcIp is None and mask == int("ffffffff", 16))
            srcIp = val
        elif(off == 16):
            assert(dstIp is None and mask == int("ffffffff", 16))
            dstIp = val
        elif(off == 20 and mask == int("0000ffff", 16)):
            assert(dstPort is None)
            dstPort = val
        elif(off == 20 and mask == int("ffff0000", 16)):
            assert(srcPort is None)
            srcPort = (val & 0xffff0000) >> 16
        elif(off == 20 and mask == int("ffffffff", 16)):
            assert(srcPort is None and dstPort is None)
            srcPort = (val & 0xffff0000) >> 16
            dstPort = val & 0x0000ffff
        else:
            raise RuntimeError("Could not parse filter line: " + _)
    
    return Filter(qdiscId, classId, srcIp, srcPort, dstIp, dstPort) 


# class htb 1:1 root prio 0 quantum 10000 rate 800000bit ceil 800000bit burst 1599b/1 mpu 0b overhead 0b cburst 1599b/1 mpu 0b overhead 0b level 0
# class htb 1:1 root prio 0 quantum 12500 rate  1000Kbit ceil  1000Kbit burst 1600b/1 mpu 0b overhead 0b cburst 1600b/1 mpu 0b overhead 0b level 0
# class htb 1:1 root prio 0 quantum 1000  rate  10000bit ceil  10000bit burst 1600b/8 mpu 0b overhead 0b cburst 1600b/8 mpu 0b overhead 0b level 0
# class htb 1:1 root leaf 20:   prio 0 quantum 125000 rate 10000Kbit ceil 10000Kbit                    burst 1600b/1 mpu 0b overhead 0b cburst 1600b/1 mpu 0b overhead 0b level 0
# class htb 1:1 root leaf 8001: prio 0 quantum 12500  rate 1000Kbit  ceil 1000Kbit  linklayer ethernet burst 1600b/1 mpu 0b overhead 0b cburst 1600b/1 mpu 0b overhead 0b level 0
def parseClassLine(cl):

    L = cl.split()
    if len(L) == 26:
        assert(L[0] == "class" and L[1] == "htb" and L[3] == "root" and L[4] == "prio" and L[5] == "0"
               and L[6] == "quantum" and L[8] == "rate" and L[10] == "ceil" and L[12] == "burst"
               and L[14] == "mpu" and L[15] == "0b" and L[16] == "overhead" and L[17] == "0b" and L[18] == "cburst"
               and L[20] == "mpu" and L[21] == "0b" and L[22] == "overhead" and L[23] == "0b" and L[24] == "level"
               and L[25] == "0")
        ind_rate = 9
        ind_ceil = 11
        ind_burst = 13
        ind_cburst = 19
    elif len(L) == 28:
        assert(L[0] == "class" and L[1] == "htb" and L[3] == "root" and L[4] == "leaf" and L[6] == "prio"
               and L[7] == "0" and L[8] == "quantum" and L[10] == "rate" and L[12] == "ceil" and L[14] == "burst"
               and L[16] == "mpu" and L[17] == "0b" and L[18] == "overhead" and L[19] == "0b" and L[20] == "cburst"
               and L[22] == "mpu" and L[23] == "0b" and L[24] == "overhead" and L[25] == "0b" and L[26] == "level"
               and L[27] == "0")
        ind_rate = 11
        ind_ceil = 13
        ind_burst = 15
        ind_cburst = 21
    elif len(L) == 30:
        assert(L[0] == "class" and L[1] == "htb" and L[3] == "root" and L[4] == "leaf" and L[6] == "prio"
               and L[7] == "0" and L[8] == "quantum" and L[10] == "rate" and L[12] == "ceil" 
               and L[14] == 'linklayer' and L[15] == 'ethernet'
               and L[16] == "burst"
               and L[18] == "mpu" and L[19] == "0b" and L[20] == "overhead" and L[21] == "0b" and L[22] == "cburst"
               and L[24] == "mpu" and L[25] == "0b" and L[26] == "overhead" and L[27] == "0b" and L[28] == "level"
               and L[29] == "0")
        ind_rate = 11
        ind_ceil = 13
        ind_burst = 17
        ind_cburst = 23
    else:
        raise RuntimeError("Cannot parse class line: {}.".format(cl))

    LL = L[2].split(":")
    assert(len(LL) == 2)
    qdisc_id = int(LL[0])
    class_id = int(LL[1])

    # parse rate
    if L[ind_rate].endswith("Kbit"):
        rate = 1000 * int(L[ind_rate][:-4])
    elif L[ind_rate].endswith("Mbit"):
        rate = 1000000 * int(L[ind_rate][:-4])
    elif L[ind_rate].endswith("bit"):
        rate = int(L[ind_rate][:-3])

    # parse ceil
    if L[ind_ceil].endswith("Kbit"):
        ceil = 1000 * int(L[ind_ceil][:-4])
    elif L[ind_ceil].endswith("Mbit"):
        ceil = 1000000 * int(L[ind_ceil][:-4])
    elif L[ind_ceil].endswith("bit"):
        ceil = int(L[ind_ceil][:-3])

    # parse burst
    LL = L[ind_burst].split("/")
    assert(len(LL) == 2 and LL[0].endswith("b"))
    burst = int(LL[0][:-1])

    # parse cburst
    LL = L[ind_cburst].split("/")
    assert(len(LL) == 2 and LL[0].endswith("b"))
    cburst = int(LL[0][:-1])

    return Class(qdisc_id, class_id, rate, ceil, burst, cburst)


def getExistingTrafficControls(dev, checkConsistency = False):
    
    # parse qdiscs
    ret = subprocess.check_output([tcCmd, "-d", "qdisc", "show", "dev",  dev])
    ret = ret.splitlines()
    assert(len(ret) >= 1)
    
    if ret[0].startswith("qdisc pfifo_fast 0: root"):
        assert(len(ret) == 1)
        assert(not subprocess.check_output([tcCmd, "-d", "class", "show", "dev", dev]))
        assert(not subprocess.check_output([tcCmd, "filter", "show", "dev", dev]))
        return []
    elif ret[0].startswith("qdisc mq 0: root"):
        raise RuntimeError("Not implemented. (Wireless interface???)")
    
    qdiscs = []
    bfifos = []
    
    for line in ret:
        L = line.split()
        assert(L[0] == "qdisc")
        if L[1] == "htb":
            assert(len(L) > 4 and L[3] == "root")
            LL = L[2].split(":")
            assert(len(LL) == 2 and LL[1] == "")
            qdiscs.append(Qdisc(int(LL[0])))
        elif L[1] == "bfifo":
            assert(len(L) == 7 and L[3] == "parent" and L[5] == "limit" and L[6][-1] == "b")
            LL = L[2].split(":")
            assert(len(LL) == 2 and LL[1] == "")
            handle = int(LL[0])
            LL = L[4].split(":")
            assert(len(LL) == 2)
            qdisc_id = int(LL[0])
            class_id = int(LL[1])
            limit = int(L[6][:-1])
            bfifos.append(Bfifo(qdisc_id, class_id, handle, limit))
        else:
            raise RuntimeError("Unexpected qdisc: {}.".format(L[1]))
    assert(len(qdiscs) == 1)
    
    # parse classes
    ret = subprocess.check_output([tcCmd, "-d", "class", "show", "dev", dev], shell=False)
    ret = ret.splitlines()
    assert(len(ret) == len(bfifos))
    
    for line in ret:
        c = parseClassLine(line)
        
        found = False
        for q in qdiscs:
            if q.qdiscId == c.qdiscId:
                assert(not found)
                found = True
                q.classes.append(c)
        assert found

        found = False
        for bf in bfifos:
            if bf.qdisc_id == c.qdiscId and bf.class_id == c.classId:
                assert(not found)
                found = True
                c.bfifo = bf
        assert found
            
    # parse filters
    ret = subprocess.check_output([tcCmd, "filter", "show", "dev", dev])
    ret = ret.splitlines()
    
    # cut first two lines
    if(len(ret) > 2 and ret[0].startswith("filter parent") and ret[1].startswith("filter parent")\
           and not "flowid" in ret[0] and not "flowid" in ret[1]):
        ret = ret[2:]
    else:
        assert(not checkConsistency)
     
    while(ret):
        
        # parse one filter
        filterLines = []
        assert(ret[0].startswith("filter parent"))
        filterLines.append(ret[0])
        ret = ret[1:]
        while(ret and not ret[0].startswith("filter parent")):
            filterLines.append(ret[0])
            ret = ret[1:]
        f = parseFilterLines(filterLines)
        
        # find class for this filter and append filter to class
        found = False
        for q in qdiscs:
            if(q.qdiscId == f.qdiscId):
                for c in q.classes:
                    if(c.classId == f.classId):
                        #assert(not found and not c.filters)
                        found = True
                        c.filters.append(f) 
        assert(found)
        
    # sanity checks
    '''if(checkConsistency):
        for q in qdiscs:
            for c in q.classes:
                assert(len(c.filters) == 1)
    else:
        for q in qdiscs:
            for c in q.classes:
                assert(len(c.filters) <= 1)'''
        
    return qdiscs


# rate is in [bps]
def trafficControlNew(dev, srcIp, srcPort, dstIp, dstPort, rate, max_delay):

    assert(stringIpToNum(srcIp) == stringIpToNum(getOwnIp(dev)))
    
    # get existing filters
    qdiscs = getExistingTrafficControls(dev)
    if not qdiscs:
        subprocess.check_call([tcCmd, "qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "99"])
        qdiscs = getExistingTrafficControls(dev, False)
    else:
        assert(len(qdiscs) == 1 and qdiscs[0].qdiscId == 1)
        
    # find the first available class ID
    done = False
    for classId in range(1, 100):
        found = False
        for c in qdiscs[0].classes:
            if classId == c.classId:
                found = True
                break
        if not found:
            subprocess.check_call([tcCmd, "class", "add", "dev", dev, "parent", "1:", "classid", "1:" + str(classId),
                                   "htb", "rate", str(rate)])
            subprocess.check_call([tcCmd, "qdisc", "add", "dev", dev, "parent", "1:" + str(classId),
                                   "bfifo", "limit", str(int(rate / 8.0 * max_delay))])
            done = True
            break
    assert done
    
    if dstPort is None:
        dstPort = [None]
     
    for dp in dstPort:
        filterString = []
        if srcIp is not None:
            filterString.extend(["match", "ip", "src", srcIp])
        if srcPort is not None:
            filterString.extend(["match", "ip", "sport", str(srcPort), "0xffff"])
        if dstIp is not None:
            filterString.extend(["match", "ip", "dst", dstIp])
        if dp is not None:
            filterString.extend(["match", "ip", "dport", str(dp), "0xffff"])
        assert filterString
        subprocess.check_call([tcCmd, "filter", "add", "dev", dev, "protocol", "ip", "parent", "1:", "prio", str(1),
                               "u32"]
                              + filterString
                              + ["flowid", "1:" + str(classId)])


def trafficControlShow(dev):
    
    qdiscs = getExistingTrafficControls(dev)
    for q in qdiscs:
        print(q)


def trafficControlStop(dev):
    
    doStop = False
    qdiscs = []
    try:
        qdiscs = getExistingTrafficControls(dev)
    except AssertionError:
        doStop = True
    
    if(qdiscs or doStop):
        print("Stopping ...")
        cmd = [tcCmd, "qdisc", "del", "dev", dev, "root"]
        subprocess.call(cmd, shell=False)
        print("... done.")
        return 
    else:
        print("Nothing to be stopped.")
        return
    

def main():
    
    argv = sys.argv[1:]
    
    try:
        parser = ArgumentParser()
        parser.add_argument("action", help="Action to perform", type=str, choices=["show", "new", "stop"])
        parser.add_argument("dev", help="Network interface (e.g., eth0)", type=str)
        parser.add_argument("--src-port", dest="srcPort", metavar="srcPort", help="Source port", type=int)
        parser.add_argument("--dst-ip", dest="dstIp", metavar="dstIp", help="Destination IP", type=str)
        parser.add_argument("--dst-port", dest="dstPort", metavar="dstPort", help="Destination port", type=int,
                            action='append')
        parser.add_argument("--rate", dest="rate", metavar="rate", help="Rate limit in [bps]", type=int)
        parser.add_argument("--max-delay", dest="maxDelay", metavar="maxDelay", help="Maximum queuing delay in [s].",
                            type=float, default=0.1)
        
        # process options
        args = parser.parse_args(argv)

        # sanity checks
        if args.dstIp is not None and args.dstIp == "127.0.0.1":
            print("Warning: You are trying to limit traffic on the local loop. Don't know if it works.")
         
        srcIp = getOwnIp(args.dev)
             
        if args.action == "show":
            if args.srcPort or args.rate or args.dstIp or args.dstPort:
                print("You can only specify the network interface with the show command.")
                return 1
            trafficControlShow(args.dev)
            
        elif args.action == "new":
            if not args.rate:
                print("You must specify a rate. ")
                return 1
            elif not args.srcPort and not args.dstIp and not args.dstPort:
                print("You must specify at least one of the following: srcPort, dstIp, dstPort.")
                return 1
            elif args.dstPort and len(args.dstPort) > 2:
                print("You can specify at most two destination ports.")
            trafficControlNew(args.dev, srcIp, args.srcPort, args.dstIp, args.dstPort, args.rate, args.maxDelay)
        
        elif args.action == "stop":
            if args.srcPort or args.dstIp or args.dstPort or args.rate:
                print("You can only specify the network interface with the stop command.")
                return 1
            trafficControlStop(args.dev)
        
    except Exception, e:
        sys.stderr.write(repr(e) + "\n")
        traceback.print_exc()
        return 2

    return 0

if __name__ == "__main__":
    sys.exit(main())
    
