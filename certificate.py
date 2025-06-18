"""
Creator: Arizona Edwards
Created: 2024-05-14
"""

import os
import sys
from typing import ClassVar

from OpenSSL import crypto

from config import DebugLevel


class Certificate:
    EMPTY_CERT: ClassVar[dict] = {
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
        "cert": None,
    }

    @staticmethod
    def get_X509_cert_info(cert):  # noqa: N802
        certificate_info = {
            "subject": dict(cert.get_subject().get_components()),
            "issuer": dict(cert.get_issuer().get_components()),
            "version": cert.get_version(),
            "serialNumber": cert.get_serial_number(),
            "notBefore": cert.get_notBefore().decode("utf-8"),
            "notAfter": cert.get_notAfter().decode("utf-8"),
            "subjectAltName": cert.subjectAltName()
            if hasattr(cert, "subjectAltName")
            else "-no-such-",
            "full_dict": cert.__dict__,
            "cert": cert,
        }
        try:
            pubkey = cert.get_pubkey()
            certificate_info["publicKeyType"] = type(pubkey)
            ckey = pubkey.to_cryptography_key()
            certificate_info["cryptoKeyType"] = type(ckey)
            pnum = ckey.public_numbers()
            certificate_info["publicNumbersType"] = type(pnum)
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

    @staticmethod
    def get_cert_info(options, cert):
        if options.is_info_on():
            print(f"Cert object has type {type(cert)}")
        if isinstance(cert, crypto.X509):
            certificate_info = Certificate.get_X509_cert_info(cert)
        elif isinstance(cert, dict):
            certificate_info = {
                "subject": cert["subject"],
                "issuer": cert["issuer"],
                "version": cert["version"],
                "serialNumber": cert["serialNumber"],
                "notBefore": cert["notBefore"],
                "notAfter": cert["notAfter"],
                "subjectAltName": cert["subjectAltName"]
                if "subjectAltName" in cert
                else "-no-such-",
                "full_dict": cert,
                "cert": cert,
            }
        else:
            print(f"Cert object has type {type(cert)} with directory: ", cert.__dir__())
            certificate_info = {"full_dict": cert.__dict__, "cert": cert}
        result = Certificate.EMPTY_CERT.copy()
        result.update(certificate_info)
        return result

    @staticmethod
    def print_cert(cert, i=None, file=None, options=None):
        if file is None:
            file = sys.stdout
        index = f"{i + 1} " if i is not None else ""
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
        if options and options.is_debug_level_enabled(DebugLevel.DEBUG):
            print("  Full Dictionary:  ", cert["full_dict"], file=file)
        print("  Cert object type", type(cert), file=file)

    @staticmethod
    def print_cert_files(hostname, cert, options):
        serial_number = cert["serialNumber"] if "serialNumber" in cert else ""
        cert = cert["cert"]
        for label, contents, filename in [
            (
                "PEM",
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
                f"{serial_number}.pem" if serial_number else "",
            ),
            (
                "ASN1",
                crypto.dump_certificate(crypto.FILETYPE_ASN1, cert),
                f"{serial_number}.der" if serial_number else "",
            ),
            (
                "Text",
                crypto.dump_certificate(crypto.FILETYPE_TEXT, cert),
                f"{serial_number}.cert.txt" if serial_number else "",
            ),
        ]:
            Certificate.print_and_save_cert(
                label,
                contents,
                os.path.join(options.output_dir, f"{hostname}_{filename}"),
                options,
            )

    @staticmethod
    def print_and_save_cert(label, contents, filename, options):
        if options and options.print_cert_contents:
            print(f"\nAs {label}:")
            display = contents
            if filename and filename.endswith(".txt"):
                display = display.decode().replace("\\n", "\n")
            print(display)
        if filename and not os.path.isfile(filename):
            with open(filename, "wb") as cert_file:
                cert_file.write(contents)
