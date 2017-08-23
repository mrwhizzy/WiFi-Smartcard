"""
randTesting.py    22/08/2017

AUTHOR

    Christos Melas
    chr.melas@gmail.com

SYNOPSIS

    randTesting.py

DESCRIPTION

    This is a Python testing program, based on
    the serverPGP.py. This software is able to
    send random commands to the ESP32 for testing
    purposes. This program was used also in order
    to perform some specific operations repeatedly
    on the ESP32 in order to measure the time 
    that was taken in order to complete each 
    operation.
"""
import sys
import time
import numpy
import base64
import threading
import SocketServer
from random import randint
from getpass import getpass
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from socket import error as SocketError

"""
When this flag is not set, random data are being sent to the device.
This will eventually result in trying random PINs and locking the device
"""
sanitisedInputs = 1     # When this flag is set

def sendAndGetResponse(cmd):
    global command      # The command APDU
    global response     # The response APDU
    global condCommand  # Condition to wait until a new APDU command arrives
    global condResponse # Condition to wait until a response is available
    global newCommand   # Flag for the handler that there is a new command
    global processing   # Flag for the run function that the processing has finished
    global err          # Flag for the run function that an error happened

    cmdBytes = bytearray.fromhex(cmd)
    with condCommand:
        command = cmdBytes
        newCommand = 1
        processing = 1
        condCommand.notify()

    with condResponse:
        while (processing == 1):
            condResponse.wait(0)

        resp = ''.join(["%02X "%ord(x) for x in response]).strip()
        if (err == 0):
            return resp
        else:               # ESP32 was probably disconnected
            sys.exit()      # Terminate execution


def checkResp(resp):
    respLen = len(resp)
    if (resp[respLen-5] == "6" and resp[respLen-4] == "1"):
        return resp[respLen-2] + resp[respLen-1] + " "
    else:
        return "00 "


def sendCommand(cmd):
    resp = sendAndGetResponse(cmd)
    while True:
        more = checkResp(resp)
        if (more == "00 "):
            return resp

        resp = resp[:len(resp)-6] + " " + sendAndGetResponse("00 C0 00 00 " + more)


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


def promptForKeyType():
    if (sanitisedInputs == 1):
        keyType = 1
    else:
        keyType = randint(1, 3)

    return keyType


def verify(p2):
    if (sanitisedInputs == 1):
        if (p2 == "81 "):
            pw1 = "123456"
        elif (p2 == "82 "):
            pw1 = "123456"
        elif (p2 == "83 "):
            pw1 = "12345678"
        else:
            return False
    else:
        if (p2 == "81 "):
            pwTmp = numpy.random.randint(255, size=randint(1, 255))
            pw1 = "".join(map(chr, pwTmp[1:]))
        elif (p2 == "82 "):
            pwTmp = numpy.random.randint(255, size=randint(1, 255))
            pw1 = "".join(map(chr, pwTmp[1:]))
        elif (p2 == "83 "):
            pwTmp = numpy.random.randint(255, size=randint(1, 255))
            pw1 = "".join(map(chr, pwTmp[1:]))
        else:
            return False

    pw = " ".join("{:02x}".format(ord(c)) for c in pw1) + " "
    command = "00 20 00 " + p2 + '{0:02X}'.format(int(len(pw)/3)) + " " + pw
    if (sendCommand(command) == "90 00"):
        print "\tSuccessfully verified"
        return True
    else:
        print "\tVerification failed"
        getPWBytes()
        return False


def verifySelect():
    print "(1) VERIFY"

    select = -1
    while True:
        select = randint(0, 3)

        inval = False
        if (select == 0):
            return
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
                verify(p2)
            select = -1


def changeReferenceData():
    select = -1
    print "(2) CHANGE REFERENCE DATA"
    while True:
        try:
            select = randint(1, 2)
        except ValueError:
            pass

        if (select == 0):
            return
        elif (select == 1):
            if (sanitisedInputs == 1):
                pw = "123456"
                newPW = "123456"
            else:
                pwTmp = numpy.random.randint(255, size=randint(1, 127))
                pw = "".join(map(chr, pwTmp[1:]))
                pwTmp = numpy.random.randint(255, size=randint(1, 127))
                newPW = "".join(map(chr, pwTmp[1:]))
            mode = "81 "
            break
        elif (select == 2):
            if (sanitisedInputs == 1):
                pw ="12345678"
                newPW = "12345678"
            else:
                pwTmp = numpy.random.randint(255, size=randint(1, 127))
                pw = "".join(map(chr, pwTmp[1:]))
                pwTmp = numpy.random.randint(255, size=randint(1, 127))
                newPW = "".join(map(chr, pwTmp[1:]))
            mode = "83 "
            break
        else:
            print "Invalid option\n"
        select = -1

    pwStr = " ".join("{:02x}".format(ord(c)) for c in pw) + " "
    newStr = " ".join("{:02x}".format(ord(c)) for c in newPW) + " "
    data = pwStr + newStr
    command = "00 24 00 " + mode + '{0:02X}'.format(int(len(data)/3)) + " " + data
    if (sendCommand(command) == "90 00"):
        print "\tOperation completed successfully\n"
        return True
    else:
        print "\tOperation failed"
        getPWBytes()
        return False


def resetRetryCounter():
    select = -1
    print "(3) RESET RETRY COUNTER"
    while True:
        try:
            select = randint(1, 2)
        except ValueError:
            pass

        if (select == 0):
            return
        elif (select == 1):
            if (sanitisedInputs == 1):
                pw = "12345678"
            else:
                pwTmp = numpy.random.randint(255, size=randint(1, 127))
                pw = "".join(map(chr, pwTmp[1:]))

            mode = "00 "
            break
        elif (select == 2):
            if (not (verify("83 "))):
                return False

            mode = "02 "
            break
        else:
            print "Invalid option\n"
        select = -1

    if (sanitisedInputs == 1):
        newPW = "123456"
    else:
        pwTmp = numpy.random.randint(255, size=randint(1, 127))
        newPW = "".join(map(chr, pwTmp[1:]))

    newStr = " ".join("{:02x}".format(ord(c)) for c in newPW) + " "
    if (select == 1):
        pwStr = " ".join("{:02x}".format(ord(c)) for c in pw) + " "
        data = pwStr + newStr
    else:
        data = newStr

    command = "00 2C " + mode + "81 " + '{0:02X}'.format(int(len(data)/3)) + " " + data
    if (sendCommand(command) == "90 00"):
        print "\tOperation completed successfully\n"
        return True
    else:
        print "\tOperation failed"
        return False


def performOperation(head):
    while True:
        if (sanitisedInputs == 1):
            inpTmp = numpy.random.randint(25, size=randint(1, 245+1))+65
        else:
            inpTmp = numpy.random.randint(255, size=randint(1, 255))
        inp = "".join(map(chr, inpTmp[1:]))
        inpS = " ".join("{:02x}".format(ord(c)) for c in inp) + " "
        command = head + '{0:02X}'.format(int(len(inpS)/3)) + " " + inpS
        return sendCommand(command)


def reverseOp(inp, filename, passwd):
        cip = ''.join(chr(x) for x in bytearray.fromhex(inp))
        f = open(filename, 'r')
        key = RSA.importKey(f.read(), passphrase = passwd)
        f.close()
        plain = key.encrypt(cip, "")
        plStr = ''.join(["%02X "%ord(x) for x in plain[0]]).strip()
        padding = plStr.find("FF 00 ") + 6
        print "Reverse Operation: " + plain[0][padding/3:] + "\n"


def computeDigSign():
    if (not (verify("81 "))):
        return False

    select = -1
    print "\tCompute Digital Signature"
    resp = performOperation("00 2A 9E 9A ")
    if (resp == "6A 88"):
        print "\tSignature key not found\n"
    elif (resp == "69 83"):
        print "\tOperation Blocked\n"
    elif (resp == "6F 00"):
        print "\tUnknown Error\n"
    else:
        print "\tOperation Completed"


def sendChain(dataIn, INS):
    bytesSent = 0
    bytesToSend = len(dataIn)/3
    while (bytesToSend > 0):
        if (bytesToSend > 254):
            CLA = "10 "
            LC = "FE "
            tmpData = dataIn[bytesSent*3:(bytesSent+254)*3]
            bytesToSend = bytesToSend - 254
            bytesSent = bytesSent + 254
            apdu = CLA+INS+LC+tmpData
            sendCommand(apdu)
        else:
            CLA = "00 "
            LC = '{0:02X}'.format(bytesToSend) + " "
            tmpData = dataIn[bytesSent*3:]
            bytesToSend = 0
            apdu = CLA+INS+LC+tmpData
            return sendCommand(apdu)


def decipher():
    if (not (verify("82 "))):
        return False

    print "\tDecipher"
    ciphertexts = []
    ciphertexts.append("cipherTest0")
    ciphertexts.append("cipherTest1")
    ciphertexts.append("cipherTest2")
    ciphertexts.append("cipherTest3")
    ciphertexts.append("cipherTest4")
    ciphertexts.append("cipherTest5")
    while True:
        filename = ciphertexts[randint(0, 5)]
        if (filename == "0"):
            return
        else: 
            try:
                f = open(filename, 'r')
                inp = f.read()
                f.close()
                break
            except IOError:
                print "No such file or directory"

    inpS = "00 " + " ".join("{:02x}".format(ord(c)) for c in inp).upper() + " "
    resp = sendChain(inpS, "2A 80 86 ")

    if (resp == "6A 88"):
        print "\tDecryption key not found\n"
    elif (resp == "69 83"):
        print "\tOperation Blocked\n"
    elif (resp == "6F 00"):
        print "\tUnknown Error\n"
    else:
        print "\tDecrypted: " + bytearray.fromhex(resp[:len(resp)-6]).decode() + "\n"


def performSecOp():
    select = -1
    print "(4) PERFORM SECURITY OPERATION"
    while True:
        try:
            select = randint(0, 2)
        except ValueError:
            pass

        if (select == 0):
            return
        elif (select == 1):
            computeDigSign()
        elif (select == 2):
            decipher()
        else:
            print "Invalid option\n"
        select = -1


def intAuth():
    if (not (verify("82 "))):
        return False

    select = -1
    print "(5) INTERNAL AUTHENTICATE"
    resp = performOperation("00 88 00 00 ")
    if (resp == "6A 88"):
        print "\tAuthentication key not found\n"
    elif (resp == "69 83"):
        print "\tOperation Blocked\n"
    elif (resp == "6F 00"):
        print "\tUnknown Error\n"
    else:
        print "\tOperation Completed"



def putFP(data, keyType):       # Generate SHA1 fingerprint
    h = SHA.new()
    h.update(data)
    hStr = h.hexdigest().upper()
    fpStr = " ".join(hStr[i:i+2] for i in range(0, len(hStr), 2)) + " "
    tagFP = getFPTag(keyType)
    lenFP = getLen(fpStr)
    apdu = "00 DA 00 "+tagFP+lenFP+fpStr

    if (sendCommand(apdu) != "90 00"):
        return False

    return True


def putTime(keyType):           # Put the current timestamp
    timest = '{0:04X}'.format(int(time.time()))
    tsStr = " ".join(timest[i:i+2] for i in range(0, len(timest), 2)) + " "
    tagTime = getTimeTag(keyType)
    lenTS = getLen(tsStr)
    apdu = "00 DA 00 "+tagTime+lenTS+tsStr
    if (sendCommand(apdu) != "90 00"):
        return False

    return True


def genAsymKey():
    if (not (verify("83 "))):
        return False

    print "(6) GENERATE ASYMMETRIC KEY"
    keyType = promptForKeyType()
    if (keyType == 0):
        return False

    keyTag = getKeyTag(keyType)
    resp = sendCommand("00 47 80 00 02 " + keyTag + "00 00")
    pub = bytearray.fromhex(resp[9*3:265*3] + resp[267*3:270*3])

    if (not (putFP(pub, keyType))):
        return False

    if (not (putTime(keyType))):
        return False

    return True


def getChallenge():
    select = -1
    print "(7) GET CHALLENGE"
    length = randint(1, 255)
    
    if (length == 0):
        return
    else:
        command = "00 84 00 00 " + '{0:02X}'.format(length) + " "
        resp = sendCommand(command)


def getARD():
    resp = sendCommand("00 CA 00 6E 00") + " "    # GET DATA - Application Related Data
    if (resp[:5] == "69 85"):
        handleTerminated()
        return False

    tmpLen = int(resp[3]+resp[4], 16)
    offset = 2
    #print "Application Related Data:\n\tApplication ID ...........: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 2

    tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    #print "\tHistorical Bytes .........: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 4

    tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    #print "\tExtended Capabilities ....: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 1

    tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    #print "\tAlgorithm Attributes\n\t\tSignature ........: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 1

    tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    #print "\t\tDecryption .......: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 1

    tmpLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    #print "\t\tAuthentication ...: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + tmpLen + 2

    #print "\tPW1 status bytes\n\t\tPW1 status .......: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tPW1 max length ...: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tRC max length ....: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tPW3 max length ...: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tPW1 remaining ....: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tRC remaining .....: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 1
    #print "\t\tPW3 remaining ....: {}".format(int(resp[offset*3]+resp[offset*3+1], 16))
    offset = offset + 3

    tmpLen = 20
    #print "\tKey Fingerprints\n\t\tSignature ........: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 20
    #print "\t\tDecryption .......: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 20
    #print "\t\tAuthentication ...: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 22

    tmpLen = 20
    #print "\tCA Fingerprints\n\t\tCA 1 .............: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 20
    #print "\t\tCA 2 .............: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 20
    #print "\t\tCA 3 .............: " + resp[offset*3:(offset+tmpLen)*3]
    offset = offset + 22

    tmpLen = 4
    tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
    tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
    #print "\tKey Generation Times\n\t\tSignature: .......: " + t
    offset = offset + 4
    tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
    tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
    #print "\t\tDecryption: ......: " + t
    offset = offset + 4
    tStr = resp[offset*3]+resp[offset*3+1]+resp[offset*3+3]+resp[offset*3+4]
    tStr = tStr+resp[offset*3+6]+resp[offset*3+7]+resp[offset*3+9]+resp[offset*3+10]
    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(tStr, 16)))
    #print "\t\tAuthentication ...: " + t + "\n"
    return True


def getLoginData():
    resp = sendCommand("00 CA 00 5E 00") + " "    # GET DATA - Login Data
    #print "\tLogin Data ...............: " + bytearray.fromhex(resp[:len(resp)-6]).decode()


def getURL():
    resp = sendCommand("00 CA 5F 50 00") + " "    # GET DATA - URL
    #print "\tPublic Key URL ...........: " + bytearray.fromhex(resp[:len(resp)-6]).decode()


def getDSCnt():
    resp = sendCommand("00 CA 00 7A 00") + " "    # GET DATA - Security Support Template
    dsCnt = int(resp[6]+resp[7]+resp[9]+resp[10]+resp[12]+resp[13], 16)
    #print "\tSignature Counter.........: {}\n".format(dsCnt)


def getCRD():
    resp = sendCommand("00 CA 00 65 00") + " "    # GET DATA - Cardholder Related Data
    nLen = int(resp[3]+resp[4], 16)
    offset = 2
    name = bytearray.fromhex(resp[offset*3:(offset+nLen)*3]).decode()
    #print "Cardholder Related Data:\n\t\tName: ............: " + name
    offset = offset + nLen + 2

    lLen = int(resp[(offset*3)+1]+resp[(offset*3)+2], 16)
    offset = offset + 1
    lang = bytearray.fromhex(resp[offset*3:(offset+lLen)*3]).decode()
    #print "\t\tLanguage prefs ...: " + lang
    offset = offset + lLen + 3


def getPWBytes():
    resp = sendCommand("00 CA 00 C4 00") + "\n"    # GET DATA - PW Status Bytes


def getData():
    print "(8) GET DATA"

    select = -1
    while True:
        try:
            select = randint(0, 4)
        except ValueError:
            pass

        if (select == 0):
            print ""
            return
        elif (select == 1):
            getARD()
            getLoginData()
            getURL()
            getDSCnt()
            getCRD()
        elif (select == 2):
            resp = sendCommand("00 CA 7F 21 00") + " "    # GET DATA - Cardholder Certificate
        elif (select == 3):
            getPWBytes()                                           # GET DATA - PW Status Bytes
        elif (select == 4):
            keyType = promptForKeyType()
            keyTag = getKeyTag(keyType)
            resp = sendCommand("00 47 81 00 02 " + keyTag + "00 00")
        select = -1


def doPut(mesg, maxInp, tag):
    while True:
        if (sanitisedInputs == 1):
            inpTmp = numpy.random.randint(25, size=randint(1, maxInp+1))+65
        else:
            inpTmp = numpy.random.randint(255, size=randint(1, 255))            
        inp = "".join(map(chr, inpTmp[1:]))
        if (len(inp) <= maxInp):
            break

    iStr = " ".join("{0:02x}".format(ord(c)) for c in inp).upper() + " "
    if (sendCommand("00 DA " + tag + getLen(iStr) + iStr) == "90 00"):
        print "\tOperation completed successfully\n"
    else:
        print "\tOperation failed\n"


def importKey():
    while True:
        filename = "private.pem"
        try:
            f = open(filename, 'r')
            break
        except IOError:
            print "No such file or directory"

    while True:
        pw = "12345678"
        try:
            r = RSA.importKey(f.read(), passphrase = pw)
            f.close()
            break
        except ValueError:
            print "Wrong password"
            f.seek(0)

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
    keyType = promptForKeyType()
    if (keyType == 0):
        return False

    keyTag = getKeyTag(keyType)
    lenStr = lenE+lenP+lenQ+lenPQ+lenDP+lenDQ+lenN
    offset = "00 7F 48 " + getLen(lenStr)
    lenAll = getLen(keyTag+offset+lenStr+lenFull+full)
    data = (TAG+lenAll+keyTag+offset+lenStr+lenFull+full)

    if (sendChain(data, "DB 3F FF ") != "90 00"):
        return False

    pub = bytearray.fromhex(nStr+eStr)          # Get the public elements of the key
    if (not (putFP(pub, keyType))):
        return False

    if (not (putTime(keyType))):
        return False

    return True


def putData():
    if (not (verify("83 "))):
        return False

    print "(9) PUT DATA"
    select = randint(1, 9)
    if (select == 0):
        return
    elif (select == 1):
        doPut("name (Max. 39 characters): ", 39, "00 5B ")
    elif (select == 2):
        doPut("login data (Max. 254 characters): ", 254, "00 5E ")
    elif (select == 3):
        doPut("language preferences (Max. 8 characters): ", 8, "5F 2D ")
    elif (select == 4):
        if (randint(0, 1) == 0):
            sex = "31 "
        else:
            sex = "32 "

        if (sendCommand("00 DA 5F 35 01 " + sex) == "90 00"):
            print "\tOperation completed successfully\n"
        else:
            print "\tOperation failed\n"
    elif (select == 5):
        doPut("URL (Max. 254 characters): ", 254, "5F 50 ")
    elif (select == 6):
        doPut("cardholder certificate (Max. 1216 characters): ", 1216, "7F 21 ")
    elif (select == 7):
        while True:
            inp = randint(0, 1)
            if (int(inp) == 0):
                val = "00 "
                break
            elif (int(inp) == 1):
                val = "01 "
                break

        if (sendCommand("00 DA 00 C4 01 " + val) == "90 00"):
            print "\tOperation completed successfully\n"
        else:
            print "\tOperation failed\n"
    elif (select == 8):
        print "\tRESETTING CODE"
        pw1 = "12345678"

        pStr = " ".join("{0:02x}".format(ord(c)) for c in pw1).upper() + " "
        if (sendCommand("00 DA 00 D3 " + getLen(pStr) + pStr) == "90 00"):
            print "Operation completed successfully\n"
        else:
            print "Operation failed\n"
    elif (select == 9):
        print "\tIMPORT KEY"
        if (importKey()):
            print "\tThe key was imported successfully\n"
        else:
            print "\tKey import failed\n"
    else:
        print "Invalid option\n"


def handleTerminated():
    print "(10) TERMINATE"
    select = -1
    while True:
        print "Please enter the type of operation you would like to perform:"
        print "\t(1) ACTIVATE"
        print "\t(0) Back\n"

        try:
            select = int(raw_input("Your selection: "))
        except ValueError:
            pass

        if (select == 0):
            return
        elif (select == 1):
            if (sendCommand("00 44 00 00 00") == "90 00"):
                print "\tOperation completed successfully\n"
                return
            else:
                print "\tOperation failed\n"
        else:
            return
        select = -1


def getByteNumber(mesg):
    while True:
        print mesg
        try:
            number = int(raw_input("Max value: 255, enter 0 to cancel: "))
            if (0 <= number < 256):
                break
            else:
                print "Invalid option\n"
        except ValueError:
            print "Invalid option\n"
    return number


def setPinRetries():
    if (not (verify("83 "))):
        return False

    print "(13) SET RETRIES"
    p1 = 3
    rc = 3
    p3 = 3
    c = "00 F2 00 00 03" + '{0:02X}'.format(p1) + '{0:02X}'.format(rc) + '{0:02X}'.format(p3) + " "
    if (sendCommand(c) == "90 00"):
        print "\tOperation completed successfully\n"
    else:
        print "\tOperation failed\n"


class handleConnection(SocketServer.BaseRequestHandler):
    def handle(self):
        global command      # The command APDU
        global response     # The response APDU
        global condCommand  # Condition to wait until a new APDU command arrives
        global condResponse # Condition to wait until a response is available
        global newCommand   # Flag for the handler that there is a new command
        global processing   # Flag for the run function that the processing has finished
        global err          # Flag for the run function that an error happened

        with condCommand:
            while (newCommand == 0):
                condCommand.wait()

        with condResponse:
            try:
                self.request.sendall(command)   # Send the command APDU to the ESP32
                response = self.request.recv(257).strip()   # Get the response APDU
            except SocketError:     # ESP32 probably disconnected
                err = 1             # Set the error flag

            processing = 0          # Processing finished, got the response
            newCommand = 0          # Reset the newCommand flag
            condResponse.notify()


if __name__ == '__main__':
    HOST, PORT = '10.42.0.1', 5511

    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), handleConnection)
    srvThrd = threading.Thread(target=server.serve_forever)
    srvThrd.daemon = True
    srvThrd.start()

    global command      # The command APDU
    global response     # The response APDU
    global condCommand  # Condition to wait until a new APDU command arrives
    global condResponse # Condition to wait until a response is available
    global newCommand   # Flag for the handler that there is a new command
    global processing   # Flag for the run function that the processing has finished
    global err          # Flag for the run function that an error happened

    condCommand = threading.Condition()
    condResponse = threading.Condition()

    while True:
        newCommand = 0
        processing = 0
        command = ""
        response = ""
        err = 0
        while True:     # Check for terminated status
            if (getARD() == True):
                break

        select = randint(1, 13)
        if (select == 0):
            print "\n\t(0) QUIT\n"
            sys.exit()      # Terminate execution
        elif (select == 1):
            verifySelect()
        elif (select == 2):
            changeReferenceData()
        elif (select == 3):
            resetRetryCounter()
        elif (select == 4):
            performSecOp()
        elif (select == 5):
            intAuth()
        elif (select == 6):
            if (genAsymKey()):
                print "\tKey generated successfully"
            else:
                print "\tKey generation failed"
        elif (select == 7):
            getChallenge()
        elif (select == 8):
            getData()
        elif (select == 9):
            putData()
        elif (select == 10):
            if (sendCommand("00 E6 00 00 00") == "90 00"):
                print "(10) TERMINATE\n\tOperation completed successfully\n"
            else:
                print "(10) TERMINATE\n\tOperation failed\n"
        elif (select == 11):
            print "(11) ACTIVATE"
            if (sendCommand("00 44 00 00 00") == "90 00"):
                print "\tOperation completed successfully\n"
            else:
                print "\tOperation failed\n"
        elif (select == 12):
            print "(12) GET VERSION"
            resp = sendCommand("00 F1 00 00 00")
            print "\tVersion: " + resp[:len(resp)-6] + "\n"
        elif (select == 13):
            setPinRetries()
