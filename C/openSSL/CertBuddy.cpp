/*
 * OpenSSL.cpp
 *
 *  Created on: Mar 28, 2014
 *      Author: rakesh
 */

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "CertBuddy.h"

const char *CertBuddy::CA_DEF_COUNTRY = "US";
const char *CertBuddy::CA_DEF_ORG = "ActMobile";
const char *CertBuddy::CA_DEF_COMMON_NAME = "AM Root CA";

CertBuddy::CertBuddy()
{
	this->m_ca = create_ca(CA_DEF_COUNTRY, CA_DEF_ORG, CA_DEF_COMMON_NAME);
}

CertBuddy::CertBuddy(CertBuddy_CA CA)
{
	this->m_ca = CA;
}

CertBuddy::~CertBuddy()
{
	// TODO Auto-generated destructor stub
}

void CertBuddy::setCA(CertBuddy_CA ca)
{
	m_ca = ca;
}

CertBuddy_CA CertBuddy::getCA()
{
	return m_ca;
}

int CertBuddy::create_key(EVP_PKEY **pkeyp, int bits)
{
	EVP_PKEY *pk;
	RSA *rsa;

	if ((pkeyp == NULL) || (*pkeyp == NULL))
	{
		if ((pk = EVP_PKEY_new()) == NULL)
		{
			return 0;	// Error
		}
	}
	else
		pk = *pkeyp;

	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
	{
		return 0;	// Error
	}
	rsa = NULL;

	*pkeyp = pk;

	return 1;
}

int CertBuddy::create_cert(X509 **x509p, EVP_PKEY **pkeyp, const char *country,
		const char* org, const char* common_name)
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

	if (!sign_cert(*x509p, this->m_ca))
	{
		return 0;	// Error
	}

	return 1;
}

int CertBuddy::create_new_minimal_cert(X509 **x509p, EVP_PKEY **pkeyp)
{
	X509 *x;
	long serial_number = CertBuddy::get_random_long();

	if ((x509p == NULL) || (*x509p == NULL))
	{
		if ((x = X509_new()) == NULL)
			return 0;
	}
	else
		x = *x509p;

	if ((pkeyp == NULL) || (*pkeyp == NULL))
	{
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

int CertBuddy::sign_cert(X509 *cert, CertBuddy_CA ca)
{
	X509_set_issuer_name(cert, ca.Name);

	if (!X509_sign(cert, ca.Pkey, EVP_md5()))
		return 0;	// Error

	return 1;
}

void CertBuddy::add_CA_ext(X509 *cert)
{

	/* Add various extensions: standard extensions */
	add_ext(cert, NID_basic_constraints,
			const_cast<char *>("critical,CA:TRUE"));
	add_ext(cert, NID_key_usage,
			const_cast<char *>("critical,keyCertSign,cRLSign"));

	add_ext(cert, NID_subject_key_identifier, const_cast<char *>("hash"));

	/* Some Netscape specific extensions */
	add_ext(cert, NID_netscape_cert_type, const_cast<char *>("sslCA"));
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
int CertBuddy::add_ext(X509 *cert, int nid, char *value)
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

int CertBuddy::set_subject(X509_NAME **name, const char* country,
		const char* org, const char* common_name)
{
	if (name == NULL)
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

int CertBuddy::create_name(X509_NAME **name, const char* country,
		const char* org, const char* common_name)
{
	*name = X509_NAME_new();
	if (name == NULL)
	{
		return 0;
	}

	return set_subject(name, country, org, common_name);
}

long CertBuddy::get_random_long()
{
	static const char num_len = 9; // digits

	static const unsigned char numerals[] =
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	unsigned char numeral_count = sizeof(numerals);

	long int random_num = 0;

	for (int i = 0; i < num_len; ++i)
	{
		random_num *= 10;
		random_num += numerals[rand() % (numeral_count - 1)];
	}

	return random_num;
}

CertBuddy_CA CertBuddy::create_ca(const char *country, const char* org,
		const char* common_name, EVP_PKEY *pkey, X509 *x509)
{
	CertBuddy_CA ca =
	{ NULL, NULL, NULL };

	if (!create_new_minimal_cert(&x509, &pkey))
	{
		return ca;	// Error
	}

	X509_NAME *name = X509_get_subject_name(x509);

	if (!set_subject(&name, country, org, common_name))
	{
		return ca;	// Error
	}

	ca.Name = name;
	ca.Pkey = pkey;

	if (!sign_cert(x509, ca))
	{
		return ca;	// Error
	}

	ca.x509 = x509;

	return ca;
}

char * CertBuddy::to_PEM(EVP_PKEY *pkey)
{
	BIO *mem_bio = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(mem_bio, pkey->pkey.rsa, NULL, NULL, 0, NULL,
			NULL);

	size_t pub_len = BIO_pending(mem_bio);
	char *pub_key = (char *) malloc(pub_len + 1);
	BIO_read(mem_bio, pub_key, pub_len);
	//zero terminated string
	pub_key[pub_len] = '\0';

	BIO_free(mem_bio);
	return pub_key;
}

char * CertBuddy::to_PEM(X509 *x509)
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
