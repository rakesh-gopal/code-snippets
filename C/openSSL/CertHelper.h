/*
 * CertHelper.h
 *
 *  Created on: Apr 3, 2014
 *      Author: rakesh
 */

#ifndef CERTHELPER_H_
#define CERTHELPER_H_

int create_key(EVP_PKEY **pkeyp, int bits);

int create_cert(X509 **x509p, EVP_PKEY **pkeyp, const char *country,
		const char* org, const char* common_name, X509_NAME *ca_name,
		EVP_PKEY *ca_pkey);

int create_new_minimal_cert(X509 **x509p, EVP_PKEY **pkeyp);

int sign_cert(X509 *cert, X509_NAME *ca_name, EVP_PKEY *ca_pkey);

void add_CA_ext(X509 *cert);

int add_ext(X509 *cert, int nid, char *value);

int set_subject(X509_NAME **name, const char* country, const char* org,
		const char* common_name);

int create_name(X509_NAME **name, const char* country, const char* org,
		const char* common_name);

long int get_random_long();

int create_ca(const char *country, const char* org, const char* common_name,
		EVP_PKEY *pkey, X509 *x509);

char *PKEY_to_PEM(EVP_PKEY *pkey);

char* X509_to_PEM(X509 *x509);

#endif /* CERTHELPER_H_ */
