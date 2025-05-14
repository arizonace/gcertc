#!/usr/bin/env python3
import sys
import os
import io
import ssl
import socket
import time
from OpenSSL import SSL, crypto
from collections.abc import Container

# See https://docs.python.org/3/library/socket.html#socket.socket
# See https://www.pyopenssl.org/en/latest/api/ssl.html
# See https://www.pyopenssl.org/en/latest/api/crypto.html
# See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-interfaces
# See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

az_trace = True
az_debug = True
az_retrace = False
az_info = True
az_show_cert_contents = False

import certifi
ca_bundle_path = certifi.where()
if az_trace: print(f"AZ_Trace: Certifi CA bundle path: {ca_bundle_path}")

SSL_SUCCESS_STATE_STRING = b"SSL negotiation finished successfully"


def show_ssl_conn_state(s, label):
    if label is None: label = ""
    state_string = s.get_state_string()
    if az_info: print(f'Connection state "{label}": ', state_string, s.get_servername(), s.get_finished(), s.get_peer_finished())
    return state_string == SSL_SUCCESS_STATE_STRING


def test_http(s, label=None):
    if label is not None and az_info: print(f"Testing HTTP {label}.")
    try:
        if az_trace: print("Sending ...")
        sent = s.write(b'HEAD / HTTP/1.0\r\n\r\n')
        if az_trace: print(f"Sent {sent} bytes, reading ...")
        data = s.read(1)
        if data:
            if az_trace: print(f"read 1 byte '{data}'", end="")
            pending = s.pending()
            if az_trace: print(f" {pending} bytes are pending.", end="")
            if pending:
                if az_trace: print(" Reading ...")
                data = s.read(pending)
                if az_trace: print(f"read '{data}'")
            else:
                if az_trace: print()
    except Exception as e:
        print('Exception testing http: ', e)
    return show_ssl_conn_state(s, f'After HTTP Test for label "{label}"')


def check_socket_read(sock):
    if az_debug: print("Checking socket for read")
    try:
        r = sock.recv(0, socket.MSG_PEEK)
        if az_debug: print("Socket is open for reading.")
    except Exception as e:
        print("Socket is not readable: ", e)


def check_socket(sock, peek_socket=False):
    if az_debug: print("Checking socket for write")
    try:
        sock.send(b'')
        if az_debug: print("Socket is open for sending.")
    except BlockingIOError as e:
        print("Socket is open for sending and blocked: ", e)
    except ConnectionError as e:
        print("Socket is not connected: ", e)
    except Exception as e:
        print("Socket is not writable: ", e)

    if peek_socket:
        check_socket_read(sock)


EMPTY_CERT = {
            "subject": "no subject",
            "issuer": "no issuer",
            "version": "no version",
            "serialNumber": "no serialNumber",
            "notBefore": "no notBefore",
            "notAfter": "no notAfter",
            "subjectAltName": "",
            "full_dict": {},
            "publicKeyType": "",
            "cryptoKeyType": "",
            "publicNumbersType": "",
            "n": 0,
            "e": 0,
            "x": 0,
            "y": 0,
            "curve": "",
            "cert": None
        }


def get_X509_cert_info(cert):
    certificate_info = {
        "subject": dict(cert.get_subject().get_components()),
        "issuer": dict(cert.get_issuer().get_components()),
        "version": cert.get_version(),
        "serialNumber": cert.get_serial_number(),
        "notBefore": cert.get_notBefore().decode('utf-8'),
        "notAfter": cert.get_notAfter().decode('utf-8'),
        "subjectAltName": cert.subjectAltName() if hasattr(cert, "subjectAltName") else "-no-such-",
        "full_dict": cert.__dict__,
        "cert": cert
    }
    try:
        pubkey = cert.get_pubkey()
        certificate_info["publicKeyType"] = type(pubkey)
        ckey=pubkey.to_cryptography_key()
        certificate_info["cryptoKeyType"] = type(ckey)
        pnum = ckey.public_numbers()
        certificate_info["publicNumbersType"] = type(pnum)
        #if str(type(pnum)).contains("EllipticCurvePublicNumbers"):
        if "EllipticCurvePublicNumbers" in str(type(pnum)):
            certificate_info["x"] = pnum.x
            certificate_info["y"] = pnum.y
            certificate_info["curve"] = pnum.curve
        elif hasattr(pnum, "n"):
            certificate_info["n"] = pnum.n
            certificate_info["e"] = pnum.e
    except Exception as e:
        print("Exception getting fields from X509 public key: ", e)
    return certificate_info


def get_cert_info(cert):
    if az_debug: print(f"Cert object has type {type(cert)}")
    if isinstance(cert, crypto.X509):
        certificate_info = get_X509_cert_info(cert)
    elif isinstance(cert, dict):
        certificate_info = {
            "subject": cert["subject"],
            "issuer": cert["issuer"],
            "version": cert["version"],
            "serialNumber": cert["serialNumber"],
            "notBefore": cert["notBefore"],
            "notAfter": cert["notAfter"],
            "subjectAltName": cert["subjectAltName"] if "subjectAltName" in cert else "-no-such-",
            "full_dict": cert,
            "cert": cert
        }
    else:
        print(f"Cert object has type {type(cert)} with directory: ", cert.__dir__())
        certificate_info = {
            "full_dict": cert.__dict__,
            "cert": cert
        }
    result =  EMPTY_CERT.copy()
    result.update(certificate_info)
    return result


def get_certificate_chain(hostname, port=443, timeout=5):
    """
    Retrieves and displays the certificate chain of a website.

    Args:
        hostname (str): The hostname of the website (e.g., "www.google.com").
        port (int, optional): The port number to connect to (default: 443 for HTTPS).
        timeout (int, optional): Timeout for the socket connection in seconds (default: 5).

    Returns:
        list: A list of certificate dictionaries, or None if an error occurs.
    """

    o_connect_socket_on_create = False
    o_check_socket_on_create = False
    o_check_socket_after_handshake = False
    o_peek_socket_after_handshake = False
    o_tls = True
    o_context_method = SSL.TLS_CLIENT_METHOD if o_tls else SSL.SSLv23_METHOD
    o_ssl_connect = True
    o_ssl_connect_use_address = True
    o_set_client_mode = True
    o_ssl_do_handshake = False
    o_do_handshake_after_ssl_connect = False
    o_get_verified_chain = True
    o_as_cryptography = False
    o_set_connect_state_before_first_http_test = True
    o_test_http_before_wait = True
    o_wait_peer_finished = True
    o_test_http_during_wait = True
    o_test_http_after_wait = True


    certificate_chain = []
    try:
        if o_connect_socket_on_create:
            sock = socket.create_connection((hostname, port), timeout=timeout)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

        if o_check_socket_on_create:
            check_socket(sock)

        ctx = SSL.Context(o_context_method)
        ctx.load_verify_locations(cafile=ca_bundle_path)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT)
        s = SSL.Connection(ctx, sock)
        ssl_connected = show_ssl_conn_state(s, "after creation")
        s.set_tlsext_host_name(hostname.encode())

        if o_ssl_connect:
            connect_result = s.connect_ex((hostname,port))
            if az_info: print ("Connected with result: ", connect_result)
            if connect_result != 0:
                print(f"Fatal Error {connect_result} from connect operation.")
                return []
        elif o_ssl_do_handshake:
            s.do_handshake()

        ssl_connected = show_ssl_conn_state(s, f"after connect/handshake handshake={o_ssl_do_handshake}")
        if o_set_client_mode:
            s.set_connect_state()
            ssl_connected = show_ssl_conn_state(s, f"after set_connect_state")

        if not ssl_connected and o_check_socket_after_handshake:
            if az_debug: print("Checking socket after handshake")
            check_socket(sock, o_peek_socket_after_handshake)

        if not ssl_connected and o_do_handshake_after_ssl_connect:
            if az_debug: print("Doing handshake after SSL connect")
            s.do_handshake()
            ssl_connected = show_ssl_conn_state(s, f"after post-connect handshake.")

        if not ssl_connected:
            if o_set_connect_state_before_first_http_test:
                s.set_connect_state()
            ssl_connected = test_http(s, f"First HTTP Test o_set_connect_state={o_set_connect_state_before_first_http_test}")

        if not ssl_connected and o_wait_peer_finished:
            if az_debug: print("Starting wait on peer finished")
            start_wait = time.time()
            while not ssl_connected:
                ssl_connected = show_ssl_conn_state(s, f"during wait")
                if ssl_connected: break
                if time.time() - start_wait > timeout:
                    break
                if o_test_http_during_wait:
                    ssl_connected = test_http(s, "during wait")
                if not ssl_connected: time.sleep(1)
        ssl_connected = ssl_connected or show_ssl_conn_state(s, f"after wait.")

        if not ssl_connected and o_test_http_after_wait:
            ssl_connected = test_http(s, "after wait")


        if o_get_verified_chain:
            chain = s.get_verified_chain(as_cryptography=o_as_cryptography)
        else:
            chain = s.get_peer_cert_chain(as_cryptography=o_as_cryptography)
        if az_info: print("Got chain: ", chain)
        if chain is None: chain = []

        if not isinstance(chain, Container):
            print(f'Chain of type {type(chain)} is not a container. Making array from it.')
            chain = [chain]

        for cert in chain:
            if az_info: print("Got cert: ", cert)
            certificate_info = get_cert_info(cert)
            certificate_chain.append(certificate_info)

        if az_trace: print("Shutting down SSL connection.")
        s.shutdown()
        if az_trace: print("Closing socket.")
        sock.close()
        return certificate_chain
    except socket.gaierror as e:
        print(f"Error: Could not resolve hostname '{hostname}': {e}")
        return None
    except SSL.Error as e:
        print(f"Error: SSL error occurred while connecting to '{hostname}': {e}, Cause:{e.__cause__}")
        return None
    except socket.timeout:
        print(f"Error: Connection to '{hostname}' timed out.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def print_cert(cert, i=None, file=None):
    if file is None: file = sys.stdout
    index = f'{i+1} ' if i is not None else ''
    print(f"--- Certificate {index}---", file=file)
    print(f"  Subject: {cert['subject']}", file=file)
    print(f"  Issuer: {cert['issuer']}", file=file)
    print(f"  Version: {cert['version']}", file=file)
    print(f"  Serial Number: {cert['serialNumber']}", file=file)
    print(f"  Valid From: {cert['notBefore']}", file=file)
    print(f"  Valid Until: {cert['notAfter']}", file=file)
    print(f"  Alternate Names: {cert['subjectAltName']}", file=file)
    print(f"  Public Key Type: {cert['publicKeyType']}", file=file)
    print(f"  Cryptography Key Type: {cert['cryptoKeyType']}", file=file)
    print(f"  Modulus: {cert['n']:#x}", file=file)
    print(f"  Exponent: {cert['e']:#x}", file=file)
    print(f"  x: {cert['x']:#x}", file=file)
    print(f"  y: {cert['y']:#x}", file=file)
    print(f"  curve: {cert['curve']}", file=file)
    if az_debug: print("  Full Dictionary:  ", cert["full_dict"], file=file)
    print("  Cert object type", type(cert), file=file)

def y_print_cert(cert, i, files, echo=True):
    if not isinstance(files, Container): files = [files]
    if echo: files.append(sys.stdout)
    for f in files:
        print_cert(cert, i, f)

def print_and_save_cert(label, contents, filename):
    if az_show_cert_contents:
        print(f'\nAs {label}:')
        display = contents
        if filename and filename.endswith(".txt"): display = display.decode().replace("\\n", "\n")
        print(display)
    if filename and not os.path.isfile(filename):
        with open(filename, "wb") as cert_file:
            cert_file.write(contents)

def print_cert_files(hostname, cert):
    serial_number = cert['serialNumber'] if "serialNumber" in cert else ""
    cert = cert['cert']
    for label,contents,filename in [
        ("PEM",  crypto.dump_certificate(crypto.FILETYPE_PEM,  cert), f'{serial_number}.pem' if serial_number else ''),
        ("ASN1", crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), f'{serial_number}.der' if serial_number else ''),
        ("Text", crypto.dump_certificate(crypto.FILETYPE_TEXT, cert), f'{serial_number}.cert.txt' if serial_number else '')
    ]:
        print_and_save_cert(label, contents, f'{hostname}_{filename}')


def y_print(str, files, echo=True):
    if not isinstance(files, Container): files = [files]
    if echo: files.append(sys.stdout)
    for f in files:
        print(str, file=f)

def print_certificate_chain(hostname, certificate_chain):
    """
    Prints the certificate chain in a user-friendly format.

    Args:
        hostname (str): The hostname of the website.
        certificate_chain (list): A list of certificate dictionaries.
    """

    if certificate_chain:
        buffer = io.StringIO()
        y_print(f"\nCertificate Chain (length {len(certificate_chain)}) for {hostname}:\n", buffer)
        for i, cert in enumerate(certificate_chain):
            y_print_cert(cert, i, buffer)
            print_cert_files(hostname, cert)
            y_print("", buffer)
        filename = hostname + '_certchain.txt'
        with open(filename, "w") as chain_file:
            chain_file.write(buffer.getvalue())
    else:
        print(f"Could not retrieve certificate chain for {hostname}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
       print("  Usage:\n\gcertc.py [server/ip] [port]\n")
       exit(1)
    target_website = str(sys.argv[1])
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    if az_info: print(f"Getting certificate chain for {target_website}:{target_port}")
    chain = get_certificate_chain(target_website, target_port)
    if az_trace: print("Main got chain: ", chain)
    print_certificate_chain(target_website, chain)
