"""
serverPGP.py    22/07/2017

AUTHOR

    Christos Melas
    cxm661@cs.bham.ac.uk

SYNOPSIS

    serverPGP.py

DESCRIPTION

    This is a Python implementation of a server that
    the ESP32 can connect to and exchange APDUs.

    * Supports PIN verification
    * Supports importing RSA-2048 keys from file
    * Supports asymmetric key generation on the ESP32
    * Supports putData fully
    * Supports getData fully

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


def getMore(self, more):
    bytes = bytearray.fromhex("00 C0 00 00 " + more)
    self.request.sendall(bytes)

    self.data = self.request.recv(257).strip()
    return ''.join(["%02X "%ord(x) for x in self.data]).strip()


def sendAndGetResponse(self, command):
    bytes = bytearray.fromhex(command)
    self.request.sendall(bytes)

    self.data = self.request.recv(257).strip()
    resp = ''.join(["%02X "%ord(x) for x in self.data]).strip()

    while True:
        more = checkResp(resp)
        if (more == "00 "):
            return resp

        resp = resp[:len(resp)-6] + " " + getMore(self, more)


def getPWBytes(self):
    resp = sendAndGetResponse(self, "00 CA 00 C4 00") + "\n"    # GET DATA - PW Status Bytes
    print 'PW1 tries remaining: ' + resp[13] + resp[14]
    print ' RC tries remaining: ' + resp[16] + resp[17]
    print 'PW3 tries remaining: ' + resp[19] + resp[20] + "\n"


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
        getPWBytes(self)
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
        print "\t(5) GET Cardholder Related Data"
        print "\t(6) GET Application Related Data"
        print "\t(7) GET Security Support Template"
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
            resp = sendAndGetResponse(self, "00 CA 00 4F 00") + " "    # GET DATA - AID
            print "AID: " + resp[:len(resp)-6] + "\n"
        elif (select == 2):
            resp = sendAndGetResponse(self, "00 CA 00 5E 00") + " "    # GET DATA - Login Data
            print "Login Data: " + bytearray.fromhex(resp[:len(resp)-6]).decode() + "\n"
        elif (select == 3):
            resp = sendAndGetResponse(self, "00 CA 5F 50 00") + " "    # GET DATA - URL
            print "URL: " + bytearray.fromhex(resp[:len(resp)-6]).decode() + "\n"
        elif (select == 4):
            resp = sendAndGetResponse(self, "00 CA 5F 52 00") + " "    # GET DATA - Historical Bytes
            print "Historical Bytes: " + resp[:len(resp)-6] + "\n"
        elif (select == 5):
            resp = sendAndGetResponse(self, "00 CA 00 65 00") + " "    # GET DATA - Cardholder Related Data
            nLen = int(resp[3]+resp[4], 16)
            offset = 2
            name = bytearray.fromhex(resp[offset*3:(offset+nLen)*3]).decode()
            print "Cardholder Related Data:\n\tName:\t\t" + name
            offset = offset + nLen + 2

            lLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            lang = bytearray.fromhex(resp[offset*3:(offset+lLen)*3]).decode()
            print "\tLanguage:\t" + lang
            offset = offset + lLen + 3

            if (resp[(offset*3)+1] == "1"):
                print "\tSex:\t\tMale\n"
            elif (resp[(offset*3)+1] == "2"):
                print "\tSex:\t\tFemale\n"
            else:
                print "\tSex:\t\tNot set\n"
        elif (select == 6):
            resp = sendAndGetResponse(self, "00 CA 00 6E 00") + " "    # GET DATA - Application Related Data
            tmpLen = int(resp[3]+resp[4], 16)
            offset = 2
            print "Application Related Data:\n\tAID:\t\t\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 2

            tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            print "\tHistorical Bytes:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 4

            tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            print "\tExtended Capabilities:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 1

            tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            print "\tAlgorithm Attributes\n\t\tSignature:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 1

            tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            print "\t\tDecryption:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 1

            tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
            offset = offset + 1
            print "\t\tAuthentication:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + tmpLen + 2

            print "\tPW1 status bytes\n\t\tPW1 status:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tPW1 max length:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tRC max length:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tPW3 max length:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tPW1 remaining:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tRC remaining:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 1
            print "\t\tPW3 remaining:\t" + resp[offset*3] + resp[offset*3+1]
            offset = offset + 3

            tmpLen = 20
            print "\tKey Fingerprints\n\t\tSignature:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 20
            print "\t\tDecryption:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 20
            print "\t\tAuthentication:\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 22

            tmpLen = 20
            print "\tCA Fingerprints\n\t\tCA 1:\t\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 20
            print "\t\tCA 2:\t\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 20
            print "\t\tCA 3:\t\t" + resp[offset*3:(offset+tmpLen)*3]
            offset = offset + 22

            tmpLen = 4
            tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
            tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
            print "\tKey Generation Times\n\t\tSignature:\t" + t
            offset = offset + 4
            tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
            tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
            print "\t\tDecryption:\t" + t
            offset = offset + 4
            tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
            tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
            print "\t\tAuthentication:\t" + t + "\n"
        elif (select == 7):
            resp = sendAndGetResponse(self, "00 CA 00 7A 00") + " "    # GET DATA - Security Support Template
            dsCnt = int(resp[6]+resp[7]+resp[9]+resp[10]+resp[12]+resp[13], 16)
            print "Digital Signature Counter: {}\n".format(dsCnt)
        elif (select == 8):
            resp = sendAndGetResponse(self, "00 CA 7F 21 00") + " "    # GET DATA - Cardholder Certificate
            print "Cardholder certificate (hex):\n" + resp[:len(resp)-6] + "\n"
        elif (select == 9):
            getPWBytes(self)                                           # GET DATA - PW Status Bytes
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
        print "\t(1) Signature\n\t(2) Decryption\n\t(3) Authentication"
        try:
            keyType = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (0 < keyType < 4):
            break

    keyTag = getKeyTag(keyType)
    resp = sendAndGetResponse(self, "00 47 80 00 02 " + keyTag + "00 00")

    print resp

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
        pw = getpass("Please enter the key password (optional): ")
        try:
            r = RSA.importKey(f.read(), passphrase = pw)
            f.close()
            break
        except ValueError:
            print "Wrong password"
            f.seek(0)

    keyType = 0
    while True:
        print "Please enter the type of the key:"
        print "\t(1) Signature\n\t(2) Decryption\n\t(3) Authentication"
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


def doPut(self, mesg, maxInp, tag):
    while True:
        inp = raw_input("\nPlease enter the " + mesg)
        if (len(inp) <= maxInp):
            break

    iStr = " ".join("{0:02x}".format(ord(c)) for c in inp).upper() + " "
    if (sendAndGetResponse(self, "00 DA " + tag + getLen(iStr) + iStr) == "90 00"):
        print "Operation completed successfully\n"
    else:
        print "Operation failed\n"


def putData(self):
    print "\nYou will need to verify the PW3 PIN"
    if (not (verify(self, "83 "))):
        return False

    select = -1
    print "\n\t(9) PUT DATA"
    while True:
        print "Please enter the type of data you would like to put:"
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
            doPut(self, "name (Max. 39 characters): ", 39, "00 5B ")
        elif (select == 2):
            doPut(self, "login data (Max. 254 characters): ", 254, "00 5E ")
        elif (select == 3):
            doPut(self, "language preferences (Max. 8 characters): ", 8, "5F 2D ")
        elif (select == 4):
            while True:
                inp = raw_input("\nPlease enter the sex (M)ale or (F)emale): ")
                if (inp == "M" or inp == "m" or inp.upper() == "MALE"):
                    sex = "31 "
                    break
                elif (inp == "F" or inp == "f" or inp.upper() == "FEMALE"):
                    sex = "32 "
                    break

            if (sendAndGetResponse(self, "00 DA 5F 35 01 " + sex) == "90 00"):
                print "Operation completed successfully\n"
            else:
                print "Operation failed\n"
        elif (select == 5):
            doPut(self, "URL (Max. 254 characters): ", 254, "5F 50 ")
        elif (select == 6):
            doPut(self, "cardholder certificate (Max. 1216 characters): ", 1216, "7F 21 ")
        elif (select == 7):
            while True:
                inp = raw_input("\nPlease enter PW1 status (0 or 1): ")
                if (int(inp) == 0):
                    val = "00 "
                    break
                elif (int(inp) == 1):
                    val = "01 "
                    break

            if (sendAndGetResponse(self, "00 DA 00 C4 01 " + val) == "90 00"):
                print "Operation completed successfully\n"
            else:
                print "Operation failed\n"
        elif (select == 8):
            while True:
                print "\nPlease enter the resetting code (RC): "
                while True:
                    pw1 = getpass("Please enter the password (Min. 8 char./Max. 127 char. or empty): ")
                    if (len(pw1) == 0 or (len(pw1) >= 8 and len(pw1) <= 127)):
                        break

                pw2 = getpass("Please confirm the password: ")
                if (pw1 == pw2):
                    break
                else:
                    print "The passwords do not match"

            pStr = " ".join("{0:02x}".format(ord(c)) for c in pw1).upper() + " "
            if (sendAndGetResponse(self, "00 DA 00 D3 " + getLen(pStr) + pStr) == "90 00"):
                print "Operation completed successfully\n"
            else:
                print "Operation failed\n"
        elif (select == 9):
            if (importKey(self)):
                print "The key was imported successfully\n"
            else:
                print "Key import failed\n"
        else:
            print "Invalid option\n"
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
                # TODO: remember to set pw1_status before PSO:CDS
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
                    print "Put data success"
                else:
                    print "Put data failed/cancelled"
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