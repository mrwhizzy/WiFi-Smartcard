"""
serverPGP.py    22/07/2017

AUTHOR

    Christos Melas
    cxm661@student.bham.ac.uk

SYNOPSIS

    serverPGP.py

DESCRIPTION

    This is a Python implementation of a server that
    the ESP32 can connect to and exchange APDUs.

    * Supports importing RSA-2048 keys from file

"""
import sys
import time
import SocketServer
from Crypto.PublicKey import RSA


def getLen(argStr):
    tmpLen = len(argStr)/3
    if (tmpLen < 128):
        return '{0:02X}'.format(int(tmpLen)) + " "
    elif (tmpLen < 256):
        return '81 {0:02X}'.format(int(tmpLen)) + " "
    else:
        longLen = '{0:04X}'.format(int(tmpLen))
        return "82 " + " ".join(longLen[i:i+2] for i in range(0, len(longLen), 2)) + " "


def getKey(key):
    if (key == "1"):
        return "B6 "
    elif (key == "2"):
        return "B8 "
    elif (key == "3"):
        return "A4 "
    else:
        return "00 "


def keyToCard(filename, pw, mode):
    f = open(filename, 'r')
    r = RSA.importKey(f.read(), passphrase = pw)

    e = '{0:06X}'.format(int(r.e))
    eStr = " ".join(e[i:i+2] for i in range(0, len(e), 2)) + " "

    p = '{0:0256X}'.format(int(r.p))
    pStr = " ".join(p[i:i+2] for i in range(0, len(p), 2)) + " "

    q = '{0:0256X}'.format(int(r.q))
    qStr = " ".join(q[i:i+2] for i in range(0, len(q), 2)) + " "

    pq = '{0:0256X}'.format(int(pow(r.q, r.p - 2, r.p)))
    pqStr = " ".join(pq[i:i+2] for i in range(0, len(pq), 2)) + " "

    dp = '{0:0256X}'.format(int(r.d % (r.p-1)))
    dpStr = " ".join(dp[i:i+2] for i in range(0, len(dp), 2)) + " "

    dq = '{0:0256X}'.format(int(r.d % (r.q-1)))
    dqStr = " ".join(dq[i:i+2] for i in range(0, len(dq), 2)) + " "

    n = '{0:0512X}'.format(int(r.n))
    nStr = " ".join(n[i:i+2] for i in range(0, len(n), 2)) + " "

    full = eStr + pStr + qStr + pqStr + dpStr + dqStr + nStr

    lenE = "91 " + getLen(eStr)
    lenP = "92 " + getLen(pStr)
    lenQ = "93 " + getLen(qStr)
    lenPQ = "94 " + getLen(pqStr)
    lenDP = "95 " + getLen(dpStr)
    lenDQ = "96 " + getLen(dqStr)
    lenN = "97 " + getLen(nStr)
    lenFull = "5F 48 " + getLen(full)

    TAG = "4D "
    keyType = getKey(mode)
    lenStr = lenE+lenP+lenQ+lenPQ+lenDP+lenDQ+lenN
    offset = "00 7F 48 " + getLen(lenStr)
    lenAll = getLen(keyType+offset+lenStr+lenFull+full)

    return (TAG+lenAll+keyType+offset+lenStr+lenFull+full)


def sendAndGetResponse(self, command):
    bytes = bytearray.fromhex(command)
    self.request.sendall(bytes)
    print '\nCommand sent to {}:'.format(self.client_address[0])
    print ' '.join(format(n,'02X') for n in bytes)

    self.data = self.request.recv(1024).strip()
    print 'Response from {}:'.format(self.client_address[0])
    print ''.join(["%02X "%ord(x) for x in self.data]).strip()


class handleConnection(SocketServer.BaseRequestHandler):
    def handle(self):
        sendAndGetResponse(self ,"00 CA 00 4F 00")                              # GET DATA - AID
        sendAndGetResponse(self ,"00 20 00 83 08 31 32 33 34 35 36 37 38")      # VERIFY - PW3
        sendAndGetResponse(self ,"00 20 00 82 06 31 32 33 34 35 36")            # VERIFY - PW1 81
        sendAndGetResponse(self ,"00 20 00 81 06 31 32 33 34 35 36")            # VERIFY - PW1 82
        sendAndGetResponse(self ,"00 47 80 00 02 B6 00 00")                     # GENERATE ASYMMETRIC KEY - SIG
        sendAndGetResponse(self ,"00 C0 00 00 0F")                              # GET RESPONSE

        # v IMPORT KEY - DEC v
        print "RSA-2048 keys supported w/ or w/out encryption"
        print "Please enter the private key filename (e.g. private.pem):",
        filename = raw_input()

        print "Please enter the key password (optional):",
        pw = raw_input()

        keyType = 0
        while (not((keyType == "1") or (keyType == "2") or (keyType == "3"))) :
            print "Please enter the type of the key:"
            print "\t(1) Sig\n\t(2) Dec\n\t(3) Auth"
            print "Your selection:",
            keyType = raw_input()

        data = keyToCard(filename, pw, keyType)

        bytesSent = 0
        bytesToSend = len(data)/3
        INS = "DB 3F FF "
        while (bytesToSend > 0):
            if (bytesToSend > 254):
                CLA = "10 "
                LC = "FE "
                tmpData = data[bytesSent*3:(bytesSent+254)*3]
                bytesToSend = bytesToSend - 254
                bytesSent = bytesSent + 254
            else:
                CLA = "00 "
                LC = '{0:02X}'.format(bytesToSend) + " "
                tmpData = data[bytesSent*3:]
                bytesToSend = 0

            apdu = CLA+INS+LC+tmpData
            sendAndGetResponse(self, apdu)

        sendAndGetResponse(self ,"00 20 00 82 06 31 32 33 34 35 36")            # VERIFY - PW1 82
                                                                                # v PERFORM SECURITY OPERATION - COMPUTE DIGITAL SIGNATURE v
        sendAndGetResponse(self ,"00 2A 9E 9A 33 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 61 48 4A AB C7 14 D5 B7 B4 A4 EE 75 DB 6A 45 20 37 66 E9 28 94 7D 2A 18 A5 5C 87 26 4A 94 87 D6 00")
        sendAndGetResponse(self, "00 C0 00 00 01")                              # GET RESPONSE
        sendAndGetResponse(self ,"00 CA 00 6E 00")                              # GET DATA - APPLICATION RELATED DATA


if __name__ == '__main__':
    HOST, PORT = '10.42.0.1', 5511

    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), handleConnection)
    server.serve_forever()