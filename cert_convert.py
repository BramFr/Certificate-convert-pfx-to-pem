#!/usr/bin/env python3
import os, sys
from OpenSSL import crypto

# pyOpenSSL 

class convertCertificat:
    def __init__(self, pkcs12file=None, password=None):
        self.CERT_NAME = pkcs12file
        self.DEFAULT_PATH = os.path.dirname(os.path.realpath(__file__)) + '/' 
        self.IN_FILE = self.DEFAULT_PATH + pkcs12file
        self.OUT_PEM = pkcs12file[:-4] + '.pem'
        self.OUT_KEY = pkcs12file[:-4] + '.key'
        self.PASSWORD = str.encode(password)
        self.PKCS12 = None
    
    def file_exists(self, location):
        return os.path.isfile(location)

    def convert_requirements(self):
        return self.file_exists(self.IN_FILE)

    def read_pkcs12_file(self):
        if self.convert_requirements():
            file = open(self.IN_FILE, 'rb').read()
            self.PKCS12 = crypto.load_pkcs12(file, passphrase=self.PASSWORD)
        return self.PKCS12 != None

    def create_pem_file(self):
        output = ''
        output += crypto.dump_certificate(crypto.FILETYPE_PEM, self.PKCS12.get_certificate()).decode("utf-8")
        for cert in self.PKCS12.get_ca_certificates():
            output += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
        out_pem = self.OUT_PEM
        self.dump_file(output, out_pem)

    def create_key_file(self):
        ouput = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.PKCS12.get_privatekey()).decode("utf-8")
        out_key = self.OUT_KEY
        self.dump_file(ouput, out_key)

    def dump_file(self, output, file):
        with open(file, 'w') as f: 
            f.write(output)
        f.close

    def convert_certificate(self):
        if self.read_pkcs12_file():
            self.create_pem_file()
            self.create_key_file()
        return self.file_exists(self.DEFAULT_PATH + self.OUT_PEM ) and self.file_exists(self.DEFAULT_PATH + self.OUT_KEY)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("incorrect parameters!")
        print("example:")
        print("python3 ./cert_convert.py certname.pfx passphrase")
        sys.exit(1)


    cert = convertCertificat(pkcs12file=sys.argv[1:][0], password=sys.argv[1:][1])
    if cert.convert_certificate():
        print("certificate converted!")