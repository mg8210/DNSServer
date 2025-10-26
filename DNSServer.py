import dns.message, dns.rdatatype, dns.rdataclass, dns.rdata, socket, threading, signal, os, sys, hashlib, base64
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=salt, length=32)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    return Fernet(key).encrypt(input_string.encode())

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    return Fernet(key).decrypt(encrypted_data).decode()

salt = b'static_salt_value'
password = "strongpassword"
input_string = "exfiltrated_data"
encrypted_value = encrypt_with_aes(input_string, password, salt)

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101'
    },
    'nyu.edu.': {
        dns.rdatatype.A: '128.122.138.132',
        dns.rdatatype.AAAA: '2001:468:1500:2::4',
        dns.rdatatype.MX: [(10, 'mx1.nyu.edu.')],
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        dns.rdatatype.TXT: (encrypted_value.decode(),)
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.0.2.45'
    }
}

def run_dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 53))
    while True:
        try:
            data, addr = s.recvfrom(1024)
            req = dns.message.from_wire(data)
            resp = dns.message.make_response(req)
            q = req.question[0]
            qname, qtype = q.name.to_text(), q.rdtype
            print(f"Responding to request for {qname} ({dns.rdatatype.to_text(qtype)})")
            if qname in dns_records and qtype in dns_records[qname]:
                adata = dns_records[qname][qtype]
                if qtype == dns.rdatatype.MX:
                    rr = dns.rrset.from_rdata(q.name, 300, *(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, srv) for pref, srv in adata))
                elif qtype == dns.rdatatype.SOA:
                    m, r, srl, ref, rtry, exp, minv = adata
                    rr = dns.rrset.from_rdata(q.name, 300, SOA(dns.rdataclass.IN, dns.rdatatype.SOA, m, r, srl, ref, rtry, exp, minv))
                elif isinstance(adata, str):
                    rr = dns.rrset.from_text(q.name, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), adata)
                else:
                    rr = dns.rrset.from_text_list(q.name, 300, dns.rdataclass.IN, dns.rdatatype.to_text(qtype), adata)
                resp.answer.append(rr)
            s.sendto(resp.to_wire(), addr)
        except KeyboardInterrupt:
            s.close(); sys.exit(0)

def run_dns_server_user():
    print("Input 'q' to quit\nDNS server is running...")
    def user_input():
        while True:
            if input().lower() == 'q':
