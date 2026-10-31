JDK-CA-CERTS(1) - General Commands Manual

# NAME

**jdk-ca-certs** - convert a certificate bundle into a JDK-compatible store

# SYNOPSIS

**jdk-ca-certs**
*in-cert.pem*
*out-jdk-cacerts*

# DESCRIPTION

The
**jdk-ca-certs**
utility converts a PEM-formatted certificate bundle into a certificate store
that can be used by the Java Development Kit
(JDK).
The JDK uses a standard PKCS#12 file whose
*certBag*s
have an Oracle-specific key usage attribute.

# EXIT STATUS

The
**jdk-ca-certs**
utility exits zero on success, and &gt;0 if an error occurs.

# SEE ALSO

openssl(1),
crypto(3),
PEM\_X509\_INFO\_read\_bio(3)

# STANDARDS

*Internet X.509 Public Key Infrastructure Certificate and CRL Profile*,
[RFC 5280](http://www.rfc-editor.org/rfc/rfc5280.html).

*PKCS #12: Personal Information Exchange Syntax v1.1*,
[RFC 7292](http://www.rfc-editor.org/rfc/rfc7292.html).

*Textual Encodings of PKIX, PKCS, and CMS Structures*,
[RFC 7468](http://www.rfc-editor.org/rfc/rfc7468.html).

# BUGS

Diagnostics are lacking and the code is not written to be portable
to operating systems other than
OpenBSD.

OpenBSD 8.0 - October 31, 2026 - JDK-CA-CERTS(1)
