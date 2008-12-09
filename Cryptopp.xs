#include <crypto++/sha.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_newCONSTSUB
#define NEED_newRV_noinc
#define NEED_sv_2pv_nolen
#define NEED_sv_2pv_flags
#include "ppport.h"
#ifdef __cplusplus
}
#endif

typedef CryptoPP::SHA1*    CryptoPPSHA1;

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::SHA1

PROTOTYPES: ENABLE

CryptoPPSHA1
Crypt::Cryptopp::SHA1::new()
CODE:
    RETVAL = new CryptoPP::SHA1();
OUTPUT:
    RETVAL

