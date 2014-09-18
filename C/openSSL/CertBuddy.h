/*
 * OpenSSL.h
 *
 *  Created on: Mar 28, 2014
 *      Author: rakesh
 */

#ifndef OPENSSL_H_
#define OPENSSL_H_

#include <openssl/x509v3.h>

class CertBuddy_CA
{
public:
	X509_NAME *Name;
	EVP_PKEY *Pkey;
	X509 *x509;
};

class CertBuddy
{
private:
	static const int KEY_LEN_BITS = 1024;
	static const int NUM_DAYS_VALID = 365;
	static const char *CA_DEF_COUNTRY;
	static const char *CA_DEF_ORG;
	static const char *CA_DEF_COMMON_NAME;

	CertBuddy_CA m_ca;

public:
	CertBuddy();
	CertBuddy(CertBuddy_CA CA);
	virtual ~CertBuddy();

	void setCA(CertBuddy_CA ca);
	CertBuddy_CA getCA();

	int create_cert(X509 **x509p, EVP_PKEY **pkeyp, const char *country,
			const char* org, const char* common_name);

	static char* to_PEM(EVP_PKEY *pkey);
	static char* to_PEM(X509 *x509);

	static CertBuddy_CA create_ca(const char *country, const char* org,
			const char* common_name, EVP_PKEY *pkey = NULL, X509 *x509 = NULL);

	static int create_key(EVP_PKEY **pkeyp, int bits);
	static int create_new_minimal_cert(X509 **x509p, EVP_PKEY **pkeyp);

private:
	static int add_ext(X509 *cert, int nid, char *value);
	static long get_random_long();
	static void add_CA_ext(X509 *cert);
	static int set_subject(X509_NAME **name, const char* country,
			const char* org, const char* common_name);
	static int sign_cert(X509 *cert, CertBuddy_CA ca);
	static int create_name(X509_NAME **name, const char* country,
			const char* org, const char* common_name);
};

#endif /* OPENSSL_H_ */
