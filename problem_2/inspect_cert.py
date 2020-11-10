# These should be all the imports you need
import binascii
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography import x509
import sys

# START - DO NOT CHANGE THE BELOW
FULL_SUBJECT = None
ISSUER = None
NOT_VALID_AFTER = None
PUBLIC_KEY_ALGORITHM = None
PUBLIC_KEY_HASH = None
PUBLIC_KEY_LENGTH = None
SERIAL_NO = None
SUBJECT_COMMON_NAME = None
VERIFIABLE = None
# END - DO NOT CHANGE


# START - DO NOT CHANGE THE BELOW
# Nothing to do here.
def print_cert_content():
    print("Issuer: {}".format(ISSUER))
    print("Subject: {}".format(FULL_SUBJECT))
    print("Subject Common Name: {}".format(SUBJECT_COMMON_NAME))
    print("Serial number: {}".format(SERIAL_NO))
    print("Expiry date: {}".format(NOT_VALID_AFTER))
    print("Public key algorithm: {}".format(PUBLIC_KEY_ALGORITHM))
    print("Public key length: {}".format(PUBLIC_KEY_LENGTH))
    print("Public Key Info hash: {}".format(PUBLIC_KEY_HASH.decode()))
    print("Signature validated: {}".format(VERIFIABLE))
# END - DO NOT CHANGE


# YOUR TASK STARTS HERE
# Reads the certificate from a file and returns a Certificate object.
def open_cert(filename):
    certfile = open(filename, 'r')
    cert_string = certfile.read().rstrip()
    cert_bytes = bytes(cert_string, 'utf-8')
    cert = x509.load_pem_x509_certificate(cert_bytes)
    return cert
# YOUR TASK ENDS HERE




# YOUR TASK STARTS HERE
# Returns the SHA256 of a public key as a hex string
# Make use of the 'hashes' functionality in cryptography.
def hash_public_key(pk):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pk)
    d = digest.finalize()
    return binascii.hexlify(d)
# YOUR TASK ENDS HERE



# Inspects a certificate passed in as a Certificate object.
def inspect_cert(cert):
    global FULL_SUBJECT, ISSUER, NOT_VALID_AFTER, PUBLIC_KEY_ALGORITHM, PUBLIC_KEY_HASH, PUBLIC_KEY_LENGTH, SERIAL_NO, SUBJECT_COMMON_NAME

    # SUBJECT: YOUR TASK STARTS HERE
    # Get full subject as RFC4515-formatted string
    subject = cert.subject.rfc4514_string().split(',')
    # RFC4514-formatted is the reversed one, so reverse it back to get RFC4515-formatted
    subject.reverse()
    FULL_SUBJECT = ','.join(subject)
    
    # Get the Common Name via x509.oid.NameOID.COMMON_NAME
    SUBJECT_COMMON_NAME = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    # YOUR TASK ENDS HERE

    # ISSUER: YOUR TASK STARTS HERE
    # Get issuer as RFC4515-formatted string
    issuer = cert.issuer.rfc4514_string().split(',')
    issuer.reverse()
    ISSUER = ','.join(issuer)
    # YOUR TASK ENDS HERE

    # EXPIRY: YOUR TASK STARTS HERE
    # Date must be formatted as YYYY-MM-DD.
    NOT_VALID_AFTER = cert.not_valid_after.isoformat()[:10]
    # YOUR TASK ENDS HERE
    
    # PUBLIC KEY ALGORITHM: YOUR TASK STARTS HERE
    p = cert.public_key()
    # p is the public key
    if isinstance(p, asymmetric.rsa.RSAPublicKey):
        PUBLIC_KEY_ALGORITHM = "RSA"
    elif isinstance(p, asymmetric.dsa.DSAPublicKey):
        PUBLIC_KEY_ALGORITHM = "DSA"
    elif isinstance(p, asymmetric.ec.EllipticCurvePublicKey):
        PUBLIC_KEY_ALGORITHM = p.curve.name
    elif isinstance(p, asymmetric.ed25519.Ed25519PublicKey):
        PUBLIC_KEY_ALGORITHM = "Ed25519"
    elif isinstance(p, asymmetric.ed448.Ed448PublicKey):
        PUBLIC_KEY_ALGORITHM = "Ed448"
    else:
        PUBLIC_KEY_ALGORITHM = "UNKNOWN"
    # YOUR TASK ENDS HERE

    # PUBLIC KEY HASH: YOUR TASK STARTS HERE
    pk_bytes = p.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    PUBLIC_KEY_HASH = hash_public_key(pk_bytes)
    # YOUR TASK ENDS HERE

    # PUBLIC KEY LENGTH: YOUR TASK STARTS HERE
    PUBLIC_KEY_LENGTH = p.key_size
    # YOUR TASK ENDS HERE

    # SERIAL NUMBER: YOUR TASK STARTS HERE
    SERIAL_NO = cert.serial_number
    # YOUR TASK ENDS HERE


def verify_cert(cert, issuer_cert):
    global VERIFIABLE
    # CHECKING THE SIGNATURE: YOUR TASK STARTS HERE
    # get the issuer's public key in its cert to decrypt the its signature
    issuer_pk = issuer_cert.public_key()
    try:
        # get the subject's signature algorithm
        sig_algo = cert.signature_algorithm_oid
        # get the certificate
        inter_cert_bytes = cert.tbs_certificate_bytes
        # get the signature
        signature = cert.signature
        # intermediate cert is signed with RSA encryption, by the CS department, the CA
        if sig_algo._name == 'sha256WithRSAEncryption':
            # verify it
            pad_scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            issuer_pk.verify(signature, inter_cert_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            VERIFIABLE = True
        # student cert is signed with EC encryption, by Ralph, the intermediate issuer
        elif sig_algo._name == 'ecdsa-with-SHA256':
            # verify it
            issuer_pk.verify(signature, inter_cert_bytes, asymmetric.ec.ECDSA(hashes.SHA256()))
            VERIFIABLE = True
    except InvalidSignature:
        print("invalid signature")
        VERIFIABLE = False
    except Exception as e:
        print("Unknown exception when verifying certificate signature. Are you trying to verify a cert that wasn't signed with RSA?")
        sys.exit(-1)
    # YOUR TASK ENDS HERE



def main():
    if len(sys.argv) != 3:
        print("Usage: python3 {} CERT ISSUER_CERT".format(sys.argv[0]))
        sys.exit(-1)
    cert = open_cert(sys.argv[1])
    issuer_cert = open_cert(sys.argv[2])
    inspect_cert(cert)
    verify_cert(cert, issuer_cert)
    print_cert_content()


if __name__ == "__main__":
    main()
