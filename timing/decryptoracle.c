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
/* A sample 1024 bit RSA key used for the selftests (public only).  */
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
  if(argc < 2)
    {
      cout<<"Usage: "<<argv[0]<< " hexadecimal-ciphertext"<<endl;
      return 1;
    }
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
    cout<<"Failure scanning private: "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  error = gcry_sexp_sscan (&pkey, NULL, sample_public_key, strlen (sample_public_key));
  if(error) {
    cout<<"Failure scanning public: "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Turn the input into an MPI
  gcry_mpi_t c = gcry_mpi_new(512);
  error = gcry_mpi_scan(&c, GCRYMPI_FMT_HEX, argv[1], 0, NULL);
  if(error) {
    cout<<"Failure scanning ciphertext: "<<argv[1]<<" "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Create the S-Expression used to do the decryption
  gcry_sexp_t forDecryption;
  char decrypt[] = "(enc-val (flags oaep unpad) (rsa (a %m)))";//flags oaep unpad
  error = gcry_sexp_build(&forDecryption, &erroff, decrypt, c);
  if(error || !forDecryption) {
    cout<<"Failure creating s-expression for decryption: "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  
  //Show what we're decrypting
  char sresult[1024];
  if(!gcry_sexp_sprint(forDecryption, GCRYSEXP_FMT_ADVANCED, sresult, 1024)) {
    cout<<"Buffer for encrypted s-expression too short"<<endl;
    return 1;
  }
  #ifdef EBUG
  cout<<"S-Expression of ciphertext:\n\t"<<sresult<<endl;
  #endif

  //Actually do the decryption
  gcry_sexp_t result;
  error = gcry_pk_decrypt(&result, forDecryption, skey);
  if(error || !result) {
    cout<<"Failure decrypting: "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }

  //Show the result of the encryption
  if(!gcry_sexp_sprint(result, GCRYSEXP_FMT_ADVANCED, sresult, 1024)) {
    cout<<"Buffer for encrypted s-expression too short"<<endl;
    return 1;
  }
  #ifdef EBUG
  cout<<"S-Expression of plaintext:\n\t"<<sresult<<endl;
  #endif

  //Get the result of the decryption:
  gcry_mpi_t r = gcry_sexp_nth_mpi (result, 1, 0);
  if(!r) {
    cout<<"Failure retrieving resulting MPI"<<endl;;
    return 1;
  }

  //Show it as a number
  unsigned char* plaintext = NULL;
  size_t plaintextLength;
  error = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &plaintext, &plaintextLength, r);
  if(error || !plaintext) {
    cout<<"Failure converting MPI r to hexadecimal: "<<error<<" "<<gcry_strsource(error)<<" / "<<gcry_strerror(error)<<endl;
    return 1;
  }
  
  cout<<plaintext<<endl;
  
  gcry_sexp_release(skey);
  gcry_sexp_release(forDecryption);
  gcry_sexp_release(result);
  return 0;
}
