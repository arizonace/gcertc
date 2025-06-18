"""
Creator: Arizona Edwards
Created: 2024-06-17

Configuration settings for the certificate chain tool.
"""

import os
from enum import IntEnum

from OpenSSL import SSL


class DebugLevel(IntEnum):
    NONE = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


# Default settings
DEFAULT_DEBUG_LEVEL = DebugLevel.INFO

# SSL settings
SSL_SUCCESS_STATE_STRING = b"SSL negotiation finished successfully"
DEFAULT_OUTPUT_DIR = "certificates"


class Options:
    """Class to hold all connection and behavior options."""

    def __init__(self):
        # Socket creation options
        self.connect_socket_on_create = False
        self.check_socket_on_create = False
        self.check_socket_after_handshake = False
        self.peek_socket_after_handshake = False

        # TLS/SSL options
        self.tls = True
        self.context_method = SSL.TLS_CLIENT_METHOD if self.tls else SSL.SSLv23_METHOD
        self.ssl_connect = True
        self.ssl_connect_use_address = True
        self.set_client_mode = True
        self.ssl_do_handshake = False
        self.do_handshake_after_ssl_connect = False
        self.get_verified_chain = True
        self.as_cryptography = False

        self.set_connect_state_before_first_http_test = True
        self.test_http_before_wait = True
        self.wait_peer_finished = True
        self.test_http_during_wait = True
        self.test_http_after_wait = True

        # Certificate options
        self.print_cert_contents = False

        # Debug options
        self.debug_level = DEFAULT_DEBUG_LEVEL
        self.output_dir = DEFAULT_OUTPUT_DIR

        # Output control options
        self.echo = True
        self.no_pem = False
        self.no_asn1 = False
        self.no_text = False

    def setup_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def get_os_filename(self, filename):
        return os.path.join(self.output_dir, filename)

    def is_debug_level_enabled(self, level: DebugLevel) -> bool:
        return self.debug_level >= level

    def is_trace_on(self) -> bool:
        return self.debug_level >= DebugLevel.TRACE

    def is_debug_on(self) -> bool:
        return self.debug_level >= DebugLevel.DEBUG

    def is_info_on(self) -> bool:
        return self.debug_level >= DebugLevel.INFO

    def is_warn_on(self) -> bool:
        return self.debug_level >= DebugLevel.WARN

    def is_error_on(self) -> bool:
        return self.debug_level >= DebugLevel.ERROR

    def __str__(self):
        return f"Options(debug_level={self.debug_level}, output_dir={self.output_dir}, echo={self.echo}, no_pem={self.no_pem}, no_asn1={self.no_asn1}, no_text={self.no_text})"

    def __repr__(self):
        return self.__str__()
