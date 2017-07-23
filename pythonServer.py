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
 
    * Supports PIN verification
    * Supports importing RSA-2048 keys from file
    * Supports asymmetric key generation on the ESP32
 
"""
import sys
import time
import binascii
import SocketServer
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from getpass import getpass


def checkResp(resp):
    respLen = len(resp)
    if (resp[respLen-5] == "6" and resp[respLen-4] == "1"):
        return resp[respLen-2] + resp[respLen-1] + " "
    else:
        return "00 "


def sendAndGetResponses(self, command, buf):
    bytes = bytearray.fromhex(command)
    self.request.sendall(bytes)

    self.data = self.request.recv(257).strip()
    resp = ''.join(["%02X "%ord(x) for x in self.data]).strip()

    while True:
        more = checkResp(resp)
        if (more == "00 "):
            return buf+resp
        else:
            tmpBuf = buf + resp[:len(resp)-6] + " "
            resp = sendAndGetResponses(self, "00 C0 00 00 "+more, tmpBuf)


def sendAndGetResponse(self, command):
    return sendAndGetResponses(self, command, "")


def verify(self, p2):
    while True:
        pw1 = getpass("Please enter the password: ")
        pw2 = getpass("Please confirm the password: ")
        if (pw1 == pw2):
            break
        else:
            print "The passwords do not match\n"

    pw = " ".join("{:02x}".format(ord(c)) for c in pw1) + " "
    command = "00 20 00 " + p2 + '{0:02X}'.format(int(len(pw)/3)) + " " + pw
    if (sendAndGetResponse(self, command) == "90 00"):
        print "\nSuccessfully verified"
        return True
    else:
        print "\nVerification failed"
        return False


def getLen(argStr):
    tmpLen = len(argStr)/3
    if (tmpLen < 128):
        return '{0:02X}'.format(int(tmpLen)) + " "
    elif (tmpLen < 256):
        return '81 {0:02X}'.format(int(tmpLen)) + " "
    else:
        longLen = '{0:04X}'.format(int(tmpLen))
        return "82 " + " ".join(longLen[i:i+2] for i in range(0, len(longLen), 2)) + " "


def getKeyTag(key):
    if (key == 1):
        return "B6 "
    elif (key == 2):
        return "B8 "
    elif (key == 3):
        return "A4 "
    else:
        return "00 "


def getFPTag(key):
    if (key == 1):
        return "C7 "
    elif (key == 2):
        return "C8 "
    elif (key == 3):
        return "C9 "
    else:
        return "00 "


def getTimeTag(key):
    if (key == 1):
        return "CE "
    elif (key == 2):
        return "CF "
    elif (key == 3):
        return "D0 "
    else:
        return "00 "


def verifySelect(self):
    print "\n\t(1) VERIFY"

    select = -1
    while True:
        print "Please enter the type of PIN you would like to verify:"
        print "\t(1) PW1 (mode 81) for PSO:CDS"
        print "\t(2) PW1 (mode 82) for other commands"
        print "\t(3) PW3 (mode 83)"
        print "\t(0) Back"
        try:
            select = int(raw_input("Your selection: "))
        except ValueError:
            pass

        inval = False
        if (select == 0):
            break
        else:
            if (select == 1):
                p2 = "81 "              # VERIFY - PW1 81
            elif (select == 2):
                p2 = "82 "              # VERIFY - PW1 82
            elif (select == 3):
                p2 = "83 "              # VERIFY - PW3
            else:
                print "Invalid option\n"
                inval = True

            if (not (inval)):
                verify(self, p2)

            select = -1


def getData(self):
    print "\n\t(8) GET DATA"

    select = -1
    while True:
        print "Please enter the type of data you would like to get:"
        print "\t(1) GET AID"
        print "\t(2) GET Login Data"
        print "\t(3) GET URL"
        print "\t(4) GET Historical Bytes"
        print "\t(5) GET Cardholder Info"
        print "\t(6) GET Application Related Data"
        print "\t(7) GET Security support template"
        print "\t(8) GET Cardholder Certificate"
        print "\t(9) GET PW Status Bytes"
        print "\t(0) Back"
        try:
            select = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (select == 0):
            break
        elif (select == 1):
            print sendAndGetResponse(self,"00 CA 00 4F 00") + "\n"      # GET DATA - AID
        elif (select == 2):
            pass#
        elif (select == 3):
            pass#
        elif (select == 4):
            pass#
        elif (select == 5):
            pass#
        elif (select == 6):
            pass#
        elif (select == 7):
            pass#
        elif (select == 8):
            pass
        elif (select == 9):
            print sendAndGetResponse(self, "00 CA 00 C4 00") + "\n"
        else:
            print "Invalid option\n"
        select = -1


def putFP(self, data, keyType):       # Generate SHA1 fingerprint
    h = SHA.new()
    h.update(data)
    hStr = h.hexdigest().upper()
    fpStr = " ".join(hStr[i:i+2] for i in range(0, len(hStr), 2)) + " "
    tagFP = getFPTag(keyType)
    lenFP = getLen(fpStr)
    apdu = "00 DA 00 "+tagFP+lenFP+fpStr

    if (sendAndGetResponse(self, apdu) != "90 00"):
        return False

    return True


def putTime(self, keyType):           # Put the current timestamp
    timest = '{0:04X}'.format(int(time.time()))
    tsStr = " ".join(timest[i:i+2] for i in range(0, len(timest), 2)) + " "
    tagTime = getTimeTag(keyType)
    lenTS = getLen(tsStr)
    apdu = "00 DA 00 "+tagTime+lenTS+tsStr
    if (sendAndGetResponse(self, apdu) != "90 00"):
        return False

    return True


def genAsymKey(self):
    print "\nYou will need to verify the PW3 PIN"
    if (not (verify(self, "83 "))):
        return False

    keyType = 0
    while True:
        print "\nPlease enter the type of the key:"
        print "\t(1) Sig\n\t(2) Dec\n\t(3) Auth"
        try:
            keyType = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (0 < keyType < 4):
            break

    keyTag = getKeyTag(keyType)
    resp = sendAndGetResponse(self, "00 47 80 00 02 " + keyTag + "00 00")

    pub = bytearray.fromhex(resp[9*3:265*3] + resp[267*3:270*3])
    if (not (putFP(self, pub, keyType))):
        return False

    if (not (putTime(self, keyType))):
        return False

    return True


def importKey(self):
    while True:
        filename = raw_input("\nPlease enter the private key filename (e.g. private.pem): ")
        try:
            f = open(filename, 'r')
            break
        except IOError:
            print "No such file or directory"

    while True:
        pw = getpass("\nPlease enter the key password (optional): ")
        try:
            r = RSA.importKey(f.read(), passphrase = pw)
            f.close()
            break
        except ValueError:
            print "Wrong password"
            f.seek(0)

    keyType = 0
    while True:
        print "\nPlease enter the type of the key:"
        print "\t(1) Sig\n\t(2) Dec\n\t(3) Auth"
        try:
            keyType = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (0 < keyType < 4):
            break

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
    keyTag = getKeyTag(keyType)
    lenStr = lenE+lenP+lenQ+lenPQ+lenDP+lenDQ+lenN
    offset = "00 7F 48 " + getLen(lenStr)
    lenAll = getLen(keyTag+offset+lenStr+lenFull+full)
    data = (TAG+lenAll+keyTag+offset+lenStr+lenFull+full)

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
        if (sendAndGetResponse(self, apdu) != "90 00"):
            return False

    pub = bytearray.fromhex(nStr+eStr)          # Get the public elements of the key
    if (not (putFP(self, pub, keyType))):
        return False

    if (not (putTime(self, keyType))):
        return False

    return True


def putData(self):
    print "\nYou will need to verify the PW3 PIN"
    if (not (verify(self, "83 "))):
        return False

    select = -1
    print "\n\t(9) PUT DATA\n"
    while True:
        print "\nPlease enter the type of data you would like to put:"
        print "\t(1) Name"
        print "\t(2) Login Data"
        print "\t(3) Language Preferences"
        print "\t(4) Sex"
        print "\t(5) URL"
        print "\t(6) Cardholder Certificate"
        print "\t(7) PW Status Bytes"
        print "\t(8) Resetting Code"
        print "\t(9) Import Key"
        print "\t(0) Back"
        try:
            select = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (select == 0):
            break
        elif (select == 1):
            pass#
        elif (select == 2):
            pass#
        elif (select == 3):
            pass#
        elif (select == 4):
            pass#
        elif (select == 5):
            pass#
        elif (select == 6):
            pass#
        elif (select == 7):
            pass#
        elif (select == 8):
            getData(self)
        elif (select == 9):
            if (importKey(self)):
                print "Key imported successfully"
            else:
                print "Key import failed"
        elif (select == 10):
            pass#
        elif (select == 11):
            pass#
        elif (select == 12):
            pass#
        elif (select == 13):
            pass#
        else:
            print "Invalid option"
        select = -1 


class handleConnection(SocketServer.BaseRequestHandler):
    def handle(self):
        print 'New connection from: {}'.format(self.client_address[0])
        select = -1
        while True:
            print "\nPlease enter the type of operation you would like to perform:"
            print "\t(1) VERIFY"
            print "\t(2) CHANGE REFERENCE DATA"
            print "\t(3) RESET RETRY COUNTER"
            print "\t(4) PERFORM SECURITY OPERATION"
            print "\t(5) INTERNAL AUTHENTICATE"
            print "\t(6) GENERATE ASYMMETRIC KEY"
            print "\t(7) GET CHALLENGE"
            print "\t(8) GET DATA"
            print "\t(9) PUT DATA"
            print "\t(10) TERMINATE DF"
            print "\t(11) ACTIVATE FILE"
            print "\t(12) GET VERSION"
            print "\t(13) SET RETRIES"
            print "\t(0) QUIT"
            try:
                select = int(raw_input("Your selection: "))
            except ValueError:
                pass

            if (select == 0):
                print "\n\t(0) QUIT\n"
                break
            elif (select == 1):
                verifySelect(self)
            elif (select == 2):
                pass#
            elif (select == 3):
                pass#
            elif (select == 4):
                pass#
            elif (select == 5):
                pass#
            elif (select == 6):
                if (genAsymKey(self)):
                    print "Key generated successfully"
                else:
                    print "Key generation failed"
            elif (select == 7):
                pass#
            elif (select == 8):
                getData(self)
            elif (select == 9):
                if (putData(self)):
                    print "Data put success"
                else:
                    print "Data put failed/cancelled"
            elif (select == 10):
                pass#
            elif (select == 11):
                pass#
            elif (select == 12):
                pass#
            elif (select == 13):
                pass#
            else:
                print "Invalid option"
            select = -1 


if __name__ == '__main__':
    HOST, PORT = '10.42.0.1', 5511

    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), handleConnection)
    server.serve_forever()