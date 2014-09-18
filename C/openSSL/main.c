/* Certificate creation. Demonstrates some certificate related
 * operations.
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <stdio.h>

#include "CertHelper.h"

int main(int argc, char **argv)
{
	// Seeding random-number generations, required for serial-number generation.
	srand(time(0));

	/*
	 * Assume that the CA cert and pkey that we are creating here,
	 * are given. We are generating them, just for the demo.
	 */
	X509 *ca_cert = NULL;
	EVP_PKEY *ca_pkey = NULL;

	create_new_minimal_cert(&ca_cert, &ca_pkey);
	create_ca("US", "ActMobile", "AM Root CA", ca_pkey, ca_cert);
	X509_NAME *ca_name = X509_get_subject_name(ca_cert);


	/*
	 * Now we start creating the signed cert.
	 */

	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	/*
	 * This call populates x509 and pkey with the cert and the private_key respectively
	 */
	create_cert(&x509, &pkey, "US", "Rakesh Gopal", "*.rakesh.com", ca_name, ca_pkey);

	/*
	 * We are using the to_PEM function to convert the private_key and cert into PEM
	 * format and it returs a pointer to the in-memory PEM.
	 */
	char *pem_p_key = PKEY_to_PEM(pkey);
	char *pem_cert = X509_to_PEM(x509);

	/*
	 * We can print-out the pem-format key and cert. That's what you see in the output.
	 */
	printf("%s\n", pem_p_key);
	printf("%s\n", pem_cert);

	/*
	 * The memory location returned by to_PEM is malloced and must be freed, before
	 * the pointer goes out of scope.
	 */
	free(pem_p_key);
	free(pem_cert);

	/*
	 * Free the X509 and EVP_PKEY memory that was allocated while creating the cert.
	 */
	X509_free(x509);
	X509_free(ca_cert);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(ca_pkey);

	return 0;
}

