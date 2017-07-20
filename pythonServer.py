import SocketServer
import time

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
        sendAndGetResponse(self ,"10 DB 3F FF FE 4D 82 03 A2 B8 00 7F 48 15 91 03 92 81 80 93 81 80 94 81 80 95 81 80 96 81 80 97 82 01 00 5F 48 82 03 83 01 00 01 D1 AF 6E 1E E2 F8 FA 86 19 BF 5C 68 F9 14 12 D5 15 28 CA AA 2B 29 32 7F A0 EA E9 D6 14 E4 A0 B7 B5 01 98 9C 13 C4 7B F5 04 46 0A 10 B6 70 A7 49 74 84 42 6D FE 25 17 8F 1A EF CF F6 3D D3 D0 E1 2B 14 5B C8 46 BA 21 4A 61 D2 9A 40 86 53 92 A6 80 35 98 45 D5 E9 3C 6C 2D 67 B4 33 48 5C 79 73 7E FC 82 4A 79 22 F4 89 7A F7 78 4F 70 85 4C 02 46 2B 9D 5F 2F 09 89 F8 3A D2 92 D4 87 F3 B5 1F F5 83 CA 6A 96 10 1D A2 03 89 78 41 30 5A FA A2 8B 4B DA 8C E1 AE 68 05 06 6F DE 69 FC 64 A7 24 A9 6A B1 B2 63 3D 00 08 74 36 23 EA F5 18 A7 7F 28 04 CC D2 31 25 EF 20 21 AB EA 97 8C 03 21 E8 5B 54 EA 64 E5 85 44 CD 4F B8 7F 8C CE 85 DC 19 C7 4C 9A 31 49 65 34 49")
        sendAndGetResponse(self ,"10 DB 3F FF FE 62 A4 8F 26 EA D2 64 1B D9 CC D3 6B 30 88 D9 2B 9F ED 02 0A 9B 60 15 B1 E1 46 9A 8B 5C 34 7B 53 1F A8 5A 89 7D B0 B0 BB 7D 51 CD CC CA 14 4D FE A8 2C D4 AB 30 13 2C 1D C8 64 AA 97 96 A6 9C 17 7A 62 E3 B3 4E 54 CC A0 73 46 8C 9E BE 09 28 7D 7F 58 09 56 9F F4 B5 9B 45 F9 92 05 44 A0 27 91 DF E1 72 C8 69 6F 0D 98 F5 E8 77 64 0D 07 13 52 C6 62 70 60 73 AE E1 D1 53 48 37 3A 58 73 F2 F3 87 41 98 36 7E 66 77 0E 39 CC E6 BE AA 52 90 DE D3 01 53 A7 46 CC B1 B9 AA 23 3B 65 B7 30 65 38 AC 3C 0D 4A 52 80 48 4F 66 5D 58 4B 27 CF 18 AE 82 BF 52 E3 C4 45 32 74 67 E2 04 1E 52 F7 C7 B9 5A DB 93 D0 79 5E AB BF 43 54 46 26 5B D8 1E 13 9D 44 7C 01 70 AF 4A 5B A7 D0 31 85 F4 FE 32 A4 20 28 56 C4 05 A6 F4 60 18 61 D5 F4 CD E2 6C 02 1E 03 6C 5E 77 B5 30 F0 AB C2 7E 56 09 79")
        sendAndGetResponse(self ,"10 DB 3F FF FE D5 8F 92 13 00 7B D0 A5 A4 7C E7 CF 69 E3 E5 83 55 12 10 BF E3 32 14 E2 5E 1A F6 1A B0 B7 19 05 75 1F 83 C7 EC FA 68 6C 67 4D 05 90 27 ED 04 5B 77 20 6D AE 16 C0 7B 65 04 5A DC 87 2A 7B 98 BD 87 F3 DD 32 79 BA B3 12 60 CB 2E DF 91 09 36 C0 72 18 BE F1 5F 1C FA D2 C5 30 D7 6A 4C 6D D2 D9 46 32 D7 30 7B 0F 56 07 D8 23 D8 B5 F2 DD B8 69 AD A6 6D 51 03 EA DF DF 1E 9E A2 EA 74 6F FB 76 C4 99 89 17 AB 7A B9 45 6D 29 48 65 20 C1 44 07 45 CC 7C 42 35 92 A1 F4 AA 69 2E 6E 98 1F E2 45 FA 29 67 05 3C 8F F2 FE 26 F3 C9 18 D6 F4 A3 78 62 CF 88 57 C5 7C 65 9B 75 35 BB 4F B3 33 2A C6 DA CF 0C BF 1D 96 6E ED 72 AF 46 CE C2 BD 23 9B 99 2E 18 CC E4 2F FE CF 44 8F 7B 20 13 D7 25 BD D7 A0 F1 90 88 5F BD 33 43 54 00 58 F8 81 96 16 FE 7F EC 0B 0A 24 AB DA DD A7 39 CA 3A 90")
        sendAndGetResponse(self ,"00 DB 3F FF AC 5F FF 16 2D C8 30 4D A5 6C 8B 2C 09 5E 1F 2E F0 DE FA 26 E5 B9 EE 92 F0 6A 4A B0 3B 22 61 6A D9 7F 7C 8B 16 F9 80 A1 FF 45 2C F6 22 5A 1E 4D DD B3 96 47 B9 04 54 6D E4 D1 C4 9E 8A 68 8D DA 93 8F 91 42 2B BC E3 CB 30 5D 27 6E B0 C3 3C 32 14 33 5C 1E 4D 2A 1C EC 95 5D 2C 56 25 D5 79 EE 89 C2 77 E0 A1 2B 7A 41 25 9D CB FE 04 46 20 24 4F 07 AD 2B B2 F1 35 3B 2B 15 63 5E DA 6F 60 C9 BD 61 DC EE 15 C2 B6 42 31 29 36 74 88 71 47 45 31 9E F4 10 50 95 1C B1 D8 30 78 AA E5 AE B2 80 EF AE C8 57 AD 81 B3 A9 4A 83 DA 9D A5")
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