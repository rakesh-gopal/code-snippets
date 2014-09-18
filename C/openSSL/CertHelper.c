/*
 * CertHelper.c
 *
 *  Created on: Apr 3, 2014
 *      Author: rakesh
 */

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "CertHelper.h"

#define NUM_DAYS_VALID 365
#define KEY_LEN_BITS 1024

int create_key(EVP_PKEY **pkeyp, int bits)
{
	EVP_PKEY *pk;
	RSA *rsa;

	if ((pkeyp == NULL )|| (*pkeyp == NULL)){
		if ((pk = EVP_PKEY_new()) == NULL)
		{
			return 0;	// Error
		}
	}
	else
		pk = *pkeyp;

	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL );
	if (!EVP_PKEY_assign_RSA(pk,rsa))
	{
		return 0;	// Error
	}
	rsa = NULL;

	*pkeyp = pk;

	return 1;
}

int create_cert(X509 **x509p, EVP_PKEY **pkeyp, const char *country,
		const char* org, const char* common_name, X509_NAME *ca_name,
		EVP_PKEY *ca_pkey)
{

	if (!create_new_minimal_cert(x509p, pkeyp))
	{
		return 0;	// Error
	}

	X509_NAME *name = X509_get_subject_name(*x509p);

	if (!set_subject(&name, country, org, common_name))
	{
		return 0;	// Error
	}

	if (!sign_cert(*x509p, ca_name, ca_pkey))
	{
		return 0;	// Error
	}

	return 1;
}

int create_new_minimal_cert(X509 **x509p, EVP_PKEY **pkeyp)
{
	X509 *x;
	long serial_number = get_random_long();

	if ((x509p == NULL )|| (*x509p == NULL)){
		if ((x = X509_new()) == NULL)
			return 0;
	}
	else
		x = *x509p;

	if ((pkeyp == NULL )|| (*pkeyp == NULL)){
		if (!create_key(pkeyp, KEY_LEN_BITS))
			return 0;	// Error
	}

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial_number);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long) 60 * 60 * 24 * NUM_DAYS_VALID);
	X509_set_pubkey(x, *pkeyp);

	*x509p = x;
	return (1);
}

int sign_cert(X509 *cert, X509_NAME *ca_name, EVP_PKEY *ca_pkey)
{
	X509_set_issuer_name(cert, ca_name);

	if (!X509_sign(cert, ca_pkey, EVP_md5()))
		return 0;	// Error

	if (!X509_sign(cert, ca_pkey, EVP_sha1()))
		return 0; // Error

	return 1;
}

void add_CA_ext(X509 *cert)
{
	/* Add various extensions: standard extensions */
	add_ext(cert, NID_basic_constraints, (char *) ("critical,CA:TRUE"));
	add_ext(cert, NID_key_usage, (char *) ("critical,keyCertSign,cRLSign"));

	add_ext(cert, NID_subject_key_identifier, (char *) ("hash"));

	/* Some Netscape specific extensions */
	add_ext(cert, NID_netscape_cert_type, (char *) ("sslCA"));
}

int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

int set_subject(X509_NAME **name, const char* country, const char* org,
		const char* common_name)
{
	if (name == NULL )
	{
		return 0;
	}

	if (!X509_NAME_add_entry_by_txt(*name, "C", MBSTRING_ASC,
			(const unsigned char *) country, -1, -1, 0))
	{
		X509_NAME_free(*name);
		return 0;
	}

	if (!X509_NAME_add_entry_by_txt(*name, "O", MBSTRING_ASC,
			(const unsigned char *) org, -1, -1, 0))
	{
		X509_NAME_free(*name);
		return 0;
	}

	if (!X509_NAME_add_entry_by_txt(*name, "CN", MBSTRING_ASC,
			(const unsigned char *) common_name, -1, -1, 0))
	{
		X509_NAME_free(*name);
		return 0;
	}

	return 1;
}

int create_name(X509_NAME **name, const char* country, const char* org,
		const char* common_name)
{
	*name = X509_NAME_new();
	if (name == NULL )
	{
		return 0;
	}

	return set_subject(name, country, org, common_name);
}

long int get_random_long()
{
	static const char num_len = 9; // digits

	static const unsigned char numerals[] =
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	unsigned char numeral_count = sizeof(numerals);

	long int random_num = 0;

	int i;

	for (i = 0; i < num_len; ++i)
	{
		random_num *= 10;
		random_num += numerals[rand() % (numeral_count - 1)];
	}

	return random_num;
}

int create_ca(const char *country, const char* org, const char* common_name,
		EVP_PKEY *pkey, X509 *x509)
{
	if (!create_new_minimal_cert(&x509, &pkey))
	{
		return 0;	// Error
	}

	X509_NAME *name = X509_get_subject_name(x509);

	if (!set_subject(&name, country, org, common_name))
	{
		return 0;	// Error
	}

	if (!sign_cert(x509, name, pkey))
	{
		return 0;	// Error
	}

	return 1;
}

char *PKEY_to_PEM(EVP_PKEY *pkey)
{
	BIO *mem_bio = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(mem_bio, pkey->pkey.rsa, NULL, NULL, 0, NULL,
			NULL );

	size_t pub_len = BIO_pending(mem_bio);
	char *pem_pkey = (char *) malloc(pub_len + 1);
	BIO_read(mem_bio, pem_pkey, pub_len);
	//zero terminated string
	pem_pkey[pub_len] = '\0';

	BIO_free(mem_bio);
	return pem_pkey;
}

char* X509_to_PEM(X509 *x509)
{
	BIO *mem_bio = BIO_new(BIO_s_mem());

	PEM_write_bio_X509(mem_bio, x509);

	size_t cert_len = BIO_pending(mem_bio);
	char *pem_cert = (char *) malloc(cert_len + 1);
	BIO_read(mem_bio, pem_cert, cert_len);
	//zero terminated string
	pem_cert[cert_len] = '\0';

	BIO_free(mem_bio);
	return pem_cert;
}
