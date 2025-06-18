# Get Certificate Chain

## Usage:
```
gcertc.py [-h] [--port PORT] [--timeout TIMEOUT] [--output-dir OUTPUT_DIR] [--debug-level {0,1,2,3,4,5}] [--echo] [--no-pem] [--no-asn1] [--no-text] hostname
```

No build system or IDE required. Just run the script with Python 3.10 or later. The defaults are sensible.

## Description:
Gets the certificate chain from a URL. Saves each certificate as a PEM file, a DER file (ASN1), and text.
Saves an additional text file with the key fields of all the certificates in the chain.

_With some help from Gemini, StackOverflow, Reddit, and Cursor._


## Motivation
A friend of mine almost got scammed by hackers impersonating a legitimate company pretending to be hiring. 
Everything about their website looked legitimate  The scammer's website was professional 
including the Careers page that listed the job, the About Us page with real people on LinkedIn, and a fully fleshed out web presence 
for a large chemical laboratory company. It even tied in with the real company's LinkedIn profiles. The email addresses were real and passed most of the authenticity tests (but not the DMARC). Even the AI tools that I used didn't detect that the website was fake. Furthermore, they made you take an aptitude test to apply for the job. I later joked that they were testing if you were dumb enough to fall for the scam.

Not satisified, I checked the certificate chain. The scammer's website had a certificate chain that looked legitimate with well known trusted CA's but it had been issued "yesterday." It had subtly modified the name of the company replacing "labs" with "laboratories". The real website had just "labs" in the name. It was not responding.

My suspicions were mostly confirmed by the date on the certifcate and the fact that it was registered in Iceland for a California company, so I decided to write a tool to make it easy to check the certificate chain of any website.

## Effort and Status

It is not very sophisticated, but it works. It could be a good starting point for more sophisticated tools but mostly it allowed me to experiment with the sequence of steps to get the certificate chain. Now that I know a valid sequence, I wouldn't write it this way again.
I don't pretend it is cross platform. In particular, the code to get the local certifcate store may need to be optional on some platforms. 
I have only tested it on MacOS 15 (Sequoia).
I struggled to get the SSL handshake to complete. In the code you will see several options for what steps to try and in what order.
In addition to the documentation, I also printed the dictionaries and directories of several Python objects to understand what was going on.

However, as it stands, it gets the job done. 


## Research

Most of the research was done on these sites:
- See https://docs.python.org/3/library/socket.html#socket.socket
- See https://www.pyopenssl.org/en/latest/api/ssl.html
- See https://www.pyopenssl.org/en/latest/api/crypto.html
- See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-interfaces
- See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
- With additional research on StackOverflow, Reddit, and Gemini. 
After getting it working I switched from VSCode to Cursor to help with tidying it up.


## Hints
I originally had it writing the certificates to the current directory. I found this command very handy:
```
rm *.pem; rm *.der; rm *.cert.txt; rm *_certchain.txt
```
Now you can specifiy the output directory which is ./certificates by default.

Usually the simplest version of the hostname should work, but you may get different results with or without various subdomains such as "www".

On MacOS if you highlight a certificate file (.der, .pem) in Finder and press the space bar, it will open a Quick Look window with the certificate details. **You DO NOT** want to ~~double click~~ on the file to open it in Keychain Access.

## Future Enhancements
- All filenames are prefixed with the hostname that was searched, not the hostname on each certificate, which is of course different for the CA's. 
- The port is alwayssys 443. If you specify a port with the : syntax it will be treated as part of the hostname.
- There is no way to force overwrite of existing files.
- DebugLevel could be symbolic, e.g. "debug", "info", "warning", "error", "trace".