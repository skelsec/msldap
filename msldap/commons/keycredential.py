from struct import pack
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
import base64
import uuid
import datetime
import time
import hashlib
import binascii
import os

# code based on:
# 
# https://podalirius.net/en/articles/parsing-the-msds-keycredentiallink-value-for-shadowcredentials-attack/
# https://github.com/MichaelGrafnetter/DSInternals
 
HASH_ALGO = hashes.SHA256()

def getTicksNow():
    # https://learn.microsoft.com/en-us/dotnet/api/system.datetime.ticks?view=net-5.0#system-datetime-ticks
    dt_now = datetime.datetime.now()
    csharp_epoch = datetime.datetime(year=1, month=1, day=1)
    delta = dt_now - csharp_epoch
    return int(delta.total_seconds() * 10000000) # Convert to microseconds and multiply by 10 for ticks

def getDeviceId():
    return uuid.uuid4().bytes

class KeyCredential:
    def __init__(self, certificate, key, deviceId, currentTime):
        self.certificate = certificate
        self.key = key
        self.pubkey = KeyCredential.raw_public_key(certificate, key)
        self.privkey = key
        self.__rawKeyMaterial = (0x3, self.pubkey)
        self.__usage = (0x4, pack("<B", 0x01))
        self.__source = (0x5, pack("<B", 0x0))
        self.__deviceId = (0x6, deviceId)
        self.__customKeyInfo = (0x7, pack("<BB", 0x1, 0x0))
        self.__lastLogonTime = (0x8, pack("<Q", currentTime))
        self.__creationTime = (0x9, pack("<Q", currentTime))
        

        self.version = 0x200

        self.thumbprint = base64.b64encode(hashlib.sha256(self.pubkey).digest()).decode("utf-8")
        self.identifier = base64.b64decode(self.thumbprint + "===")

    @staticmethod
    def raw_public_key(certificate, key):
        # Get public key numbers from cryptography
        public_key = key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Convert to bytes
        def int_to_bytes(n):
            return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        
        kSize = pack("<I", public_key.key_size)
        exponent = int_to_bytes(public_numbers.e)
        exponentSize = pack("<I", len(exponent))
        modulus = int_to_bytes(public_numbers.n)
        modulusSize = pack("<I", len(modulus))

        padding = pack("<I", 0) * 2

        return b'RSA1' + kSize + exponentSize + modulusSize + padding + exponent + modulus

    @staticmethod
    def generate_self_signed_certificate(subject, nBefore = None, nAfter = None, kSize=2048, deviceId=None, currentTime=None):
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=kSize,
        )

        if nBefore is None:
            nBefore = (-40 * 365)
        if nAfter is None:
            nAfter = (40 * 365)
        
        # Create certificate
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ])
        
        # Certificate is self-signed, so issuer is the same as subject
        issuer_name = subject_name
        
        # Create certificate builder
        cert = x509.CertificateBuilder().subject_name(
            subject_name
        ).issuer_name(
            issuer_name
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=float(nBefore))
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=float(nAfter))
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject)]),
            critical=False,
        ).sign(private_key, HASH_ALGO)

        deviceId = deviceId if deviceId is not None else getDeviceId()
        currentTime = currentTime if currentTime is not None else getTicksNow()

        return KeyCredential(cert, private_key, deviceId, currentTime)

    def packData(self, fields):
        return b''.join([pack("<HB", len(field[1]), field[0]) + field[1] for field in fields])

    def getKeyIdentifier(self):
        return (0x1, self.identifier)

    def getKeyHash(self):
        computed_hash = hashlib.sha256(self.identifier).digest()
        return (0x2, computed_hash)

    def dumpBinary(self):
        version = pack("<L", self.version)

        binaryData = self.packData([self.getKeyIdentifier(),
                                    self.getKeyHash(),
                                    ])

        binaryProperties = self.packData([self.__rawKeyMaterial,
                                          self.__usage,
                                          self.__source,
                                          self.__deviceId,
                                          self.__customKeyInfo,
                                          self.__lastLogonTime,
                                          self.__creationTime,
                                          ])

        return version + binaryData + binaryProperties
    
    def to_pfx(self, password, path_to_file):
        if len(os.path.dirname(path_to_file)) != 0:
            if not os.path.exists(os.path.dirname(path_to_file)):
                os.makedirs(os.path.dirname(path_to_file), exist_ok=True)

        # Convert to PKCS12 format using cryptography
        pfx_data = self.to_pfx_data(password)
        
        with open(path_to_file + ".pfx", "wb") as f:
            f.write(pfx_data)

    def to_pfx_data(self, password):
        return serialize_key_and_certificates(
            name=b"",
            key=self.key,
            cert=self.certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

    @staticmethod
    def from_pfx(path_to_file, password):
        with open(path_to_file, "rb") as f:
            pfx_data = f.read()
        
        return KeyCredential.from_pfx_data(pfx_data, password)

    @staticmethod
    def from_pfx_data(pfx_data, password):
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        key, cert, cas = load_key_and_certificates(pfx_data, password.encode())
        return KeyCredential(cert, key, None, None)

    def to_pem(self, path_to_file):
        if len(os.path.dirname(path_to_file)) != 0:
            if not os.path.exists(os.path.dirname(path_to_file)):
                os.makedirs(os.path.dirname(path_to_file), exist_ok=True)

        # Export certificate
        cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        with open(path_to_file + "_cert.pem", "wb") as f:
            f.write(cert_pem)
        
        # Export private key
        priv_pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(path_to_file + "_priv.pem", "wb") as f:
            f.write(priv_pem) 


    def toDNWithBinary2String(self, owner:str):
        bd = self.dumpBinary()
        hexdata = binascii.hexlify(bd).decode("UTF-8")
        return "B:%d:%s:%s" % (len(bd) * 2, hexdata, owner)

