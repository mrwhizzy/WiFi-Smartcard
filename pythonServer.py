import SocketServer
import time

class handleConnection(SocketServer.BaseRequestHandler):
    def handle(self):
        while(1):
            bytes = bytearray() # GET AID
            bytes.append(0x00)  # CLA
            bytes.append(0xCA)  # INS
            bytes.append(0x00)  # P1
            bytes.append(0x4F)  # P2
            bytes.append(0x00)  # Le
            self.request.sendall(bytes)
            print '\nCommand sent to {}:'.format(self.client_address[0])
            print ' '.join(format(n,'02X') for n in bytes)

            self.data = self.request.recv(1024).strip()
            print 'Response from {}:'.format(self.client_address[0])
            print ''.join(["%02X "%ord(x) for x in self.data]).strip()

            bytes = bytearray() # GET HISTORICAL
            bytes.append(0x00)  # CLA
            bytes.append(0xCA)  # INS
            bytes.append(0x5F)  # P1
            bytes.append(0x52)  # P2
            bytes.append(0x00)  # Le
            self.request.sendall(bytes)
            print '\nCommand sent to {}:'.format(self.client_address[0])
            print ' '.join(format(n,'02X') for n in bytes)

            self.data = self.request.recv(1024).strip()
            print 'Response from {}:'.format(self.client_address[0])
            print ''.join(["%02X "%ord(x) for x in self.data]).strip()

            bytes = bytearray() # GET Application Related Data
            bytes.append(0x00)  # CLA
            bytes.append(0xCA)  # INS
            bytes.append(0x00)  # P1
            bytes.append(0x6E)  # P2
            bytes.append(0x00)  # Le
            self.request.sendall(bytes)
            print '\nCommand sent to {}:'.format(self.client_address[0])
            print ' '.join(format(n,'02X') for n in bytes)

            self.data = self.request.recv(1024).strip()
            print 'Response from {}:'.format(self.client_address[0])
            print ''.join(["%02X "%ord(x) for x in self.data]).strip()
            time.sleep(5)


if __name__ == '__main__':
    HOST, PORT = '10.42.0.1', 5511

    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), handleConnection)
    server.serve_forever()