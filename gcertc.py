#!/usr/bin/env python3
"""
Creator: Arizona Edwards
Created: 2024-05-14
"""

import argparse
import io
import os
import socket
import sys
import time
from collections.abc import Container

import certifi
from OpenSSL import SSL, crypto

from certificate import Certificate
from config import (
    SSL_SUCCESS_STATE_STRING,
    DebugLevel,
    Options,
)

"""
Research:
# See https://docs.python.org/3/library/socket.html#socket.socket
# See https://www.pyopenssl.org/en/latest/api/ssl.html
# See https://www.pyopenssl.org/en/latest/api/crypto.html
# See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-interfaces
# See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
"""

ca_bundle_path = certifi.where()


def show_ssl_conn_state(options, s, label):
    if label is None:
        label = ""
    state_string = s.get_state_string()
    if options.is_info_on():
        print(
            f'Connection state "{label}": ',
            state_string,
            s.get_servername(),
            s.get_finished(),
            s.get_peer_finished(),
        )
    return state_string == SSL_SUCCESS_STATE_STRING


def test_http(options, s, label):
    if label is not None and options.is_info_on():
        print(f"Testing HTTP {label}.")
    try:
        if options.is_trace_on():
            print("Sending ...")
        sent = s.write(b"HEAD / HTTP/1.0\r\n\r\n")
        if options.is_trace_on():
            print(f"Sent {sent} bytes, reading ...")
        data = s.read(1)
        if data:
            if options.is_trace_on():
                print(f"read 1 byte '{data}'", end="")
            pending = s.pending()
            if options.is_trace_on():
                print(f" {pending} bytes are pending.", end="")
            if pending:
                if options.is_trace_on():
                    print(" Reading ...")
                data = s.read(pending)
                if options.is_trace_on():
                    print(f"read '{data}'")
            elif options.is_trace_on():
                print()
    except Exception as e:
        print("Exception testing http: ", e)
    return show_ssl_conn_state(options, s, f'After HTTP Test for label "{label}"')


def check_socket_read(options, sock):
    if options.is_debug_on():
        print("Checking socket for read")
    try:
        sock.recv(0, socket.MSG_PEEK)
        if options.is_debug_on():
            print("Socket is open for reading.")
    except Exception as e:
        print("Socket is not readable: ", e)


def check_socket(options, sock, peek_socket=False):
    if options.is_debug_on():
        print("Checking socket for write")
    try:
        sock.send(b"")
        if options.is_debug_on():
            print("Socket is open for sending.")
    except BlockingIOError as e:
        print("Socket is open for sending and blocked: ", e)
    except ConnectionError as e:
        print("Socket is not connected: ", e)
    except Exception as e:
        print("Socket is not writable: ", e)

    if peek_socket:
        check_socket_read(options, sock)



def get_certificate_chain(options, hostname, port, timeout):  # noqa: PLR0912, PLR0915
    certificate_chain = []
    try:
        if options.connect_socket_on_create:
            sock = socket.create_connection((hostname, port), timeout=timeout)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

        if options.check_socket_on_create:
            check_socket(options, sock, False)

        ctx = SSL.Context(options.context_method)
        ctx.load_verify_locations(cafile=ca_bundle_path)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT)
        s = SSL.Connection(ctx, sock)
        ssl_connected = show_ssl_conn_state(options, s, "after creation")
        s.set_tlsext_host_name(hostname.encode())

        if options.ssl_connect:
            connect_result = s.connect_ex((hostname, port))
            if options.is_info_on():
                print("Connected with result: ", connect_result)
            if connect_result != 0:
                print(f"Fatal Error {connect_result} from connect operation.")
                return []
        elif options.ssl_do_handshake:
            s.do_handshake()

        ssl_connected = show_ssl_conn_state(
            options, s, f"after connect/handshake handshake={options.ssl_do_handshake}"
        )
        if options.set_client_mode:
            s.set_connect_state()
            ssl_connected = show_ssl_conn_state(options, s, "after set_connect_state")

        if not ssl_connected and options.check_socket_after_handshake:
            if options.is_debug_on():
                print("Checking socket after handshake")
            check_socket(options, sock, options.peek_socket_after_handshake)

        if not ssl_connected and options.do_handshake_after_ssl_connect:
            if options.is_debug_on():
                print("Doing handshake after SSL connect")
            s.do_handshake()
            ssl_connected = show_ssl_conn_state(
                options, s, "after post-connect handshake."
            )

        if not ssl_connected:
            if options.set_connect_state_before_first_http_test:
                s.set_connect_state()
            ssl_connected = test_http(
                options,
                s,
                f"First HTTP Test o_set_connect_state={options.set_connect_state_before_first_http_test}",
            )

        if not ssl_connected and options.wait_peer_finished:
            if options.is_debug_on():
                print("Starting wait on peer finished")
            start_wait = time.time()
            while not ssl_connected:
                ssl_connected = show_ssl_conn_state(options, s, "during wait")
                if ssl_connected:
                    break
                if time.time() - start_wait > timeout:
                    break
                if options.test_http_during_wait:
                    ssl_connected = test_http(options, s, "during wait")
                if not ssl_connected:
                    time.sleep(1)
        ssl_connected = ssl_connected or show_ssl_conn_state(options, s, "after wait.")

        if not ssl_connected and options.test_http_after_wait:
            ssl_connected = test_http(options, s, "after wait")

        if options.get_verified_chain:
            chain = s.get_verified_chain(as_cryptography=options.as_cryptography)
        else:
            chain = s.get_peer_cert_chain(as_cryptography=options.as_cryptography)
        if options.is_info_on():
            print("Got chain: ", chain)
        if chain is None:
            chain = []

        if not isinstance(chain, Container):
            print(
                f"Chain of type {type(chain)} is not a container. Making array from it."
            )
            chain = [chain]

        for cert in chain:  # type: ignore
            if options.is_info_on():
                print("Got cert: ", cert)
            certificate_info = Certificate.get_cert_info(options, cert)
            certificate_chain.append(certificate_info)

        if options.is_trace_on():
            print("Shutting down SSL connection.")
        s.shutdown()
        if options.is_trace_on():
            print("Closing socket.")
        sock.close()
        return certificate_chain
    except socket.gaierror as e:
        print(f"Could not resolve hostname '{hostname}': {e}.", end=" ")
        print("Check the hostname and Internet connection and try again. Or, give up.")
        return None
    except SSL.Error as e:
        print(
            f"Did not establish SSL connection: SSL error occurred while connecting to '{hostname}': {e}, Cause:{e.__cause__}"
        )
        return None
    except socket.timeout:
        print(f"Uh Oh!: Connection to '{hostname}' timed out.")
        return None
    except Exception as e:
        print(f"Oh no! An unexpected error occurred: {e}")
        return None


def print_and_save_cert(options, label, contents, filename):
    if options.is_trace_on():
        print(f"\nAs {label}:")
        display = contents
        if filename and filename.endswith(".txt"):
            display = display.decode().replace("\\n", "\n")
        print(display)
    if filename and not os.path.isfile(filename):
        with open(filename, "wb") as cert_file:
            cert_file.write(contents)


def print_cert_files(options, hostname, cert):
    serial_number = cert["serialNumber"] if "serialNumber" in cert else ""
    cert = cert["cert"]
    formats = []
    if not options.no_pem:
        formats.append(("PEM", crypto.FILETYPE_PEM, f"{serial_number}.pem"))
    if not options.no_asn1:
        formats.append(("ASN1", crypto.FILETYPE_ASN1, f"{serial_number}.der"))
    if not options.no_text:
        formats.append(("Text", crypto.FILETYPE_TEXT, f"{serial_number}.cert.txt"))

    for label, filetype, filename in formats:
        if filename:
            contents = crypto.dump_certificate(filetype, cert)
            print_and_save_cert(options, label, contents, options.get_os_filename(f"{hostname}_{filename}"))


def y_print(options, str, files):
    if not isinstance(files, Container):
        files = [files]
    if options.echo:
        files.append(sys.stdout)  # type: ignore
    for f in files:  # type: ignore
        print(str, file=f)


def print_certificate_chain(options, hostname, certificate_chain):
    if certificate_chain:
        options.setup_output_dir()
        buffer = io.StringIO()
        y_print(
            options,
            f"\nCertificate Chain (length {len(certificate_chain)}) for {hostname}:\n",
            buffer,
        )
        for i, cert in enumerate(certificate_chain):
            Certificate.print_cert(cert, i, buffer)
            print_cert_files(options, hostname, cert)
            y_print(options, "", buffer)
        filename = options.get_os_filename(f"{hostname}_certchain.txt")
        with open(filename, "w") as chain_file:
            chain_file.write(buffer.getvalue())
    else:
        print(f"Could not retrieve certificate chain for {hostname}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Retrieve and display SSL certificate chains."
    )
    parser.add_argument("hostname", help="The hostname to check (e.g., www.google.com)")
    parser.add_argument(
        "--port", type=int, default=443, help="Port number (default: 443)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to save certificates (default: ./certificates under current directory)",
    )
    parser.add_argument(
        "--debug-level",
        type=int,
        choices=range(DebugLevel.NONE, DebugLevel.TRACE + 1),
        default=DebugLevel.INFO,
        help="Debug level (0-5, default: 3)",
    )
    parser.add_argument(
        "--echo", action="store_true", help="Echo data to terminal"
    )
    parser.add_argument("--no-pem", action="store_true", help="Do not save PEM format")
    parser.add_argument(
        "--no-asn1", action="store_true", help="Do not save ASN1 (.der) format"
    )
    parser.add_argument(
        "--no-text", action="store_true", help="Do not save text format"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    options = Options()
    options.debug_level = args.debug_level
    if args.output_dir:
        options.output_dir = args.output_dir
    options.echo = args.echo
    options.no_pem = args.no_pem
    options.no_asn1 = args.no_asn1
    options.no_text = args.no_text

    if options.is_trace_on():
        print(f"AZ_Trace: Certifi CA bundle path: {ca_bundle_path}")
        print(f"AZ_Trace: Options: {options}")
        print(f"AZ_Trace: args: {args}")

    if options.is_info_on():
        print(f"Getting certificate chain for {args.hostname}:{args.port}")

    chain = get_certificate_chain(options, args.hostname, args.port, args.timeout)
    if options.is_trace_on():
        print("Main got chain: ", chain)
    print_certificate_chain(options, args.hostname, chain)
