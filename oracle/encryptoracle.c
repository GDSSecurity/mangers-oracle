#include <iostream>
#include <string>
#include <gcrypt.h>
using namespace std;

//Source: https://github.com/GDSSecurity/mangers-oracle

static const char sample_secret_key[] =
"(private-key"
" (rsa"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
"      2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
"      ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
"      891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)"
"  (e #010001#)"
"  (d #046129f2489d71579be0a75fe029bd6cdb574ebf57ea8a5b0fda942cab943b11"
"      7d7bb95e5d28875e0f9fc5fcc06a72f6d502464dabded78ef6b716177b83d5bd"
"      c543dc5d3fed932e59f5897e92e6f58a0f33424106a3b6fa2cbf877510e4ac21"
"      c3ee47851e97d12996222ac3566d4ccb0b83d164074abf7de655fc2446da1781#)"
"  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
"      fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1#)"
"  (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
"      35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad361#)"
"  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
"      ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b#)))";
static const char sample_public_key[] =
"(public-key"
" (rsa"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
"      2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
"      ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
"      891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)"
"  (e #010001#)))";


int main(int argc, char** argv)
{
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      cout<<"libgcrypt version mismatch"<<endl;
      return 2;
    }
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  
  gcry_error_t error;
  size_t erroff;

  gcry_sexp_t skey = NULL;
  gcry_sexp_t pkey = NULL;

  error = gcry_sexp_sscan (&skey, NULL, sample_secret_key, strlen (sample_secret_key));
  if(error) {
    cout<<"Failure scanning private: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  error = gcry_sexp_sscan (&pkey, NULL, sample_public_key, strlen (sample_public_key));
  if(error) {
    cout<<"Failure scanning public: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  
  //Plaintext
  char p_cstr[] = "11223344556677889900AABBCCDDEEFF1122334455667788";
  gcry_mpi_t p = gcry_mpi_new(512);
  error = gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, p_cstr, 0, NULL);
  if(error) {
    cout<<"Failure scanning plaintext: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Create the S-Expression used to do the encryption
  gcry_sexp_t forEncryption;
  char encrypt[] = "(data (flags oaep) (value %m))";
  error = gcry_sexp_build(&forEncryption, &erroff, encrypt, p);
  if(error || !forEncryption) {
    cout<<"Failure creating s-expression for encryption: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Show what we're encrypting
  char sresult[1024];
  if(!gcry_sexp_sprint(forEncryption, GCRYSEXP_FMT_ADVANCED, sresult, 1024)) {
    cout<<"Buffer for encrypted s-expression too short"<<endl;
    return 1;
  }
  #ifdef EBUG
  cout<<"S-Expression of plaintext:\n\t"<<sresult<<endl;
  #endif
  
  //Actually do the encryption
  gcry_sexp_t result;
  error = gcry_pk_encrypt(&result, forEncryption, pkey);
  if(error || !result) {
    cout<<"Failure encrypting: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Show the result of the encryption
  if(!gcry_sexp_sprint(result, GCRYSEXP_FMT_ADVANCED, sresult, 1024)) {
    cout<<"Buffer for encrypted s-expression too short"<<endl;
    return 1;
  }
  #ifdef EBUG
  cout<<"S-Expression of ciphertext:\n\t"<<sresult<<endl;
  #endif

  //Do decryption
  gcry_sexp_t newresult;
  error = gcry_pk_decrypt(&newresult, result, skey);
  if(error || !result) {
    cout<<"Failure decrypting: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Show the result of the decryption
  if(!gcry_sexp_sprint(newresult, GCRYSEXP_FMT_ADVANCED, sresult, 1024)) {
    cout<<"Buffer for encrypted s-expression too short"<<endl;
    return 1;
  }
  #ifdef EBUG
  cout<<"S-Expression of plaintext:\n\t"<<sresult<<endl;
  #endif

  //Get the result of the encryption:
  gcry_sexp_t list = gcry_sexp_find_token (result, "a", 0);
  if(!list) {
    cout<<"Failure retrieving s-exp list"<<endl;;
    return 1;
  }
  gcry_mpi_t r = gcry_sexp_nth_mpi (list, 1, 0);
  if(!r) {
    cout<<"Failure retrieving resulting MPI"<<endl;;
    return 1;
  }
  gcry_sexp_release (list);

  //Show it as a number
  unsigned char* ciphertext = NULL;
  size_t ciphertextLength;
  error = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &ciphertext, &ciphertextLength, r);
  if(error || !ciphertext) {
    cout<<"Failure converting MPI r to hexadecimal: "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  
  cout<<ciphertext<<endl;
  
  gcry_sexp_release(pkey);
  gcry_sexp_release(forEncryption);
  gcry_sexp_release(result);
  return 0;
}
