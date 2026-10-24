/*
 * Copyright (c) 2026 Theo Buehler <tb@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "bytestring.h"

/*
 * DER encoding of the "Temporary Oracle OID"
 *
 * {joint-iso-itu-t(2) country(16) us(840) organization(1)
 *  oracle(113894) jdk(746875) crypto(1) id-at-trustedKeyUsage(1)}
 */
const uint8_t trustedKeyUsage[] = {
	0x06, 0x0c, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf9,
	0x66, 0xad, 0xca, 0x7b, 0x01, 0x01,
};

/*
 * Add DER encoding of the OID represented by nid.
 */
static int
cbb_add_nid(CBB *cbb, int nid)
{
	CBB oid, value;
	ASN1_OBJECT *obj;
	uint8_t *data = NULL;
	size_t len;
	int ret = 0;

	memset(&oid, 0, sizeof(oid));

	if ((obj = OBJ_nid2obj(nid)) == NULL)
		goto err;

	if (!CBB_init(&oid, 0))
		goto err;

	if (!CBB_add_asn1(&oid, &value, CBS_ASN1_OBJECT))
		goto err;
	if (!CBB_add_bytes(&value, OBJ_get0_data(obj), OBJ_length(obj)))
		goto err;

	if (!CBB_finish(&oid, &data, &len))
		goto err;

	if (!CBB_add_bytes(cbb, data, len))
		goto err;

	ret = 1;

 err:
	CBB_cleanup(&oid);
	free(data);

	return ret;
}

/*
 * RFC 7292, section 4.2.3
 *
 *  CertBag ::= SEQUENCE {
 *      certId      BAG-TYPE.&id   ({CertTypes}),
 *      certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
 *  }
 */
static int
cbb_add_certBag_from_cert(CBB *cbb, X509 *x509)
{
	CBB certBag, child, certValue, certDer;
	uint8_t *data = NULL, *der = NULL;
	size_t len;
	int der_len;
	int ret = 0;

	if (!CBB_init(&certBag, 0))
		goto err;

	if (!CBB_add_asn1(&certBag, &child, CBS_ASN1_SEQUENCE))
		goto err;

	/* Add certID, certValue. */
	if (!cbb_add_nid(&child, NID_x509Certificate))
		goto err;
	if (!CBB_add_asn1(&child, &certValue,
	    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0x00))
		goto err;

	/*
	 * x509Certificate BAG-TYPE ::=
	 *     {OCTET STRING IDENTIFIED BY {certTypes 1}}
	 *     -- DER-encoded X.509 certificate stored in OCTET STRING
	 */
	if (!CBB_add_asn1(&certValue, &certDer, CBS_ASN1_OCTETSTRING))
		goto err;
	if ((der_len = i2d_X509(x509, &der)) <= 0)
		goto err;
	if (!CBB_add_bytes(&certDer, der, der_len))
		goto err;

	if (!CBB_finish(&certBag, &data, &len))
		goto err;

	if (!CBB_add_bytes(cbb, data, len))
		goto err;

	ret = 1;

 err:
	CBB_cleanup(&certBag);
	free(data);
	free(der);

	return ret;
}

/*
 * The JDK only accepts PKCS#12 files with an Oracle-specific attribute.
 * Helper function to construct it. From RFC 7292, section 4.2:
 *
 * PKCS12Attribute ::= SEQUENCE {
 *     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
 *     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
 * } -- This type is compatible with the X.500 type 'Attribute'
 */
static int
cbb_add_trustedKeyUsage(CBB *cbb)
{
	CBB ku, child, attrValues;
	uint8_t *data = NULL;
	size_t len;
	int ret = 0;

	if (!CBB_init(&ku, 0))
		goto err;

	if (!CBB_add_asn1(&ku, &child, CBS_ASN1_SEQUENCE))
		goto err;

	/* Add the required oracle OID */
	if (!CBB_add_bytes(&child, trustedKeyUsage, sizeof(trustedKeyUsage)))
		goto err;

	/* And an attribute set containing the anyEKU OID. */
	if (!CBB_add_asn1(&child, &attrValues, CBS_ASN1_SET))
		goto err;
	if (!cbb_add_nid(&attrValues, NID_anyExtendedKeyUsage))
		goto err;

	if (!CBB_finish(&ku, &data, &len))
		goto err;

	if (!CBB_add_bytes(cbb, data, len))
		goto err;

	ret = 1;

 err:
	CBB_cleanup(&ku);
	free(data);

	return ret;
}

/*
 * RFC 7292, section 4.2:
 * SafeBag ::= SEQUENCE {
 *     bagId          BAG-TYPE.&id ({PKCS12BagSet})
 *     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 *     bagAttributes  SET OF PKCS12Attribute OPTIONAL
 * }
 */
static int
cbb_add_safeBag_from_cert(CBB *cbb, X509 *x509)
{
	CBB safeBag, child, bagValue, bagAttributes;
	uint8_t *data = NULL;
	size_t data_len;
	int ret = 0;

	if (!CBB_init(&safeBag, 0))
		goto err;

	if (!CBB_add_asn1(&safeBag, &child, CBS_ASN1_SEQUENCE))
		goto err;

	/* Add bagId, bagValue, bagAttributes. */
	if (!cbb_add_nid(&child, NID_certBag))
		goto err;

	if (!CBB_add_asn1(&child, &bagValue,
	    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0x00))
		goto err;
	cbb_add_certBag_from_cert(&bagValue, x509);

	if (!CBB_add_asn1(&child, &bagAttributes, CBS_ASN1_SET))
		goto err;
	cbb_add_trustedKeyUsage(&bagAttributes);

	if (!CBB_finish(&safeBag, &data, &data_len))
		goto err;

	if (!CBB_add_bytes(cbb, data, data_len))
		goto err;

	ret = 1;

 err:
	CBB_cleanup(&safeBag);
	free(data);

	return ret;
}

int
main(int argc, const char *argv[])
{
	CBB cbb;
	CBB pfx;
	CBB version, authSafe;
	CBB outerInfo, outercontent;
	CBB AuthenticatedSafe;
	CBB contentInfo, content, contentValue;
	CBB safeContents;
	uint8_t *data = NULL;
	size_t data_len;
	BIO *bio;
	const char *certpem, *outfile, *outdir;
	char *outtmp = NULL;
	STACK_OF(X509_INFO) *certs = NULL;
	int fd, i;
	FILE *file = NULL;

	memset(&cbb, 0, sizeof(cbb));

	if (argc != 3) {
		fprintf(stderr, "usage: jdk-cacerts cert.pem outfile\n");
		exit(1);
	}

	certpem = argv[1];
	outfile = argv[2];

	if (pledge("stdio rpath wpath cpath fattr unveil", NULL) == -1)
		err(1, "pledge");

	if (asprintf(&outtmp, "%s.XXXXXXXXXX", outfile) == -1)
		err(1, "asprintf");

	/* XXX - in principle dirname is allowed to modify outtmp... */
	if ((outdir = dirname(outtmp)) == NULL)
		err(1, "dirname");

	if ((fd = mkostemp(outtmp, O_CLOEXEC)) == -1)
		err(1, "mkostemp");
	if (fchmod(fd, 0644) == -1) {
		unlinkat(fd, outdir, 0);
		err(1, "fdopen");
	}
	if ((file = fdopen(fd, "w")) == NULL) {
		unlinkat(fd, outdir, 0);
		err(1, "fdopen");
	}

	if (unveil(certpem, "r") == -1) {
		warn("unveil %s", certpem);
		goto err;
	}
	if (unveil(outdir, "rwc") == -1) {
		warn("unveil %s", outfile);
		goto err;
	}

	if (pledge("stdio rpath wpath cpath", NULL) == -1) {
		warn("pledge");
		goto err;
	}

	if ((bio = BIO_new_file(certpem, "r")) == NULL)
		goto err;
	if ((certs = PEM_X509_INFO_read_bio(bio, NULL, NULL, "")) == NULL) {
		BIO_free(bio);
		goto err;
	}
	BIO_free(bio);

	if (!CBB_init(&cbb, 0))
		goto err;

	/* Create wrapping PFX PDU, RFC 7292, section 4. */
	if (!CBB_add_asn1(&cbb, &pfx, CBS_ASN1_SEQUENCE))
		goto err;

	/* RFC 7292, section 4: "version shall be v3" */
	if (!CBB_add_asn1(&pfx, &version, CBS_ASN1_INTEGER))
		goto err;
	if (!CBB_add_u8(&version, 3))
		goto err;

	/* RFC 7292, section 4: a PKCS#7 ContentInfo" */
	if (!CBB_add_asn1(&pfx, &authSafe, CBS_ASN1_SEQUENCE))
		goto err;

	/* RFC 7292, section 4.1: unencrypted, so it's id-data */
	if (!cbb_add_nid(&authSafe, NID_pkcs7_data))
		goto err;
	if (!CBB_add_asn1(&authSafe, &outerInfo,
	    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0x00))
		goto err;

	/* RFC 2315, section 8. DATA ::= OCTET STRING */
	if (!CBB_add_asn1(&outerInfo, &outercontent, CBS_ASN1_OCTETSTRING))
		goto err;

	/*
	 * RFC 7292, section 4.1: content field of the authSafe shall contain
	 * a BER-encoded value of type AuthenticatedSafe.
	 * Again of type id-data because it's unencrypted.
	 */
	if (!CBB_add_asn1(&outercontent, &AuthenticatedSafe, CBS_ASN1_SEQUENCE))
		goto err;

	if (!CBB_add_asn1(&AuthenticatedSafe, &contentInfo, CBS_ASN1_SEQUENCE))
		goto err;
	if (!cbb_add_nid(&contentInfo, NID_pkcs7_data))
		goto err;

	if (!CBB_add_asn1(&contentInfo, &content,
	    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0x00))
		goto err;
	if (!CBB_add_asn1(&content, &contentValue, CBS_ASN1_OCTETSTRING))
		goto err;

	if (!CBB_add_asn1(&contentValue, &safeContents, CBS_ASN1_SEQUENCE))
		goto err;

	for (i = 0; i < sk_X509_INFO_num(certs); i++) {
		X509_INFO *info = sk_X509_INFO_value(certs, i);

		if (info->x509 == NULL)
			continue;

		if (!cbb_add_safeBag_from_cert(&safeContents, info->x509))
			goto err;
	}
	sk_X509_INFO_pop_free(certs, X509_INFO_free);
	certs = NULL;

	if (!CBB_finish(&cbb, &data, &data_len))
		goto err;

	if (fwrite(data, data_len, 1, file) != 1)
		goto err;
	if (fclose(file) != 0) {
		file = NULL;
		goto err;
	}
	file = NULL;

	if (rename(outtmp, outfile) == -1) {
		warn("rename");
		goto err;
	}

	free(data);
	free(outtmp);

	return 0;

 err:
	warn("error writing to %s", outtmp);
	if (file != NULL)
		fclose(file);
	unlink(outtmp);

	CBB_cleanup(&cbb);
	sk_X509_INFO_pop_free(certs, X509_INFO_free);
	free(data);
	free(outtmp);

	return 1;
}
