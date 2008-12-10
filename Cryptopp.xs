#include <crypto++/cryptlib.h>
#include <crypto++/sha.h>
#include <crypto++/md2.h>
#include <crypto++/md4.h>
#include <crypto++/md5.h>
#include <crypto++/tiger.h>
#include <crypto++/crc.h>
#include <crypto++/adler32.h>
#include <crypto++/rsa.h>
#include <crypto++/ripemd.h>
#include <crypto++/whrlpool.h>
#include <crypto++/osrng.h>

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

#define PP_HASH_FINALIZE(self) do {\
    } while (0)

#define XS_STATE(type, x) \
    INT2PTR(type, SvROK(x) ? SvIV(SvRV(x)) : SvIV(x))

#define XS_STRUCT2OBJ(sv, class, obj) \
    if (obj == NULL) { \
        sv_setsv(sv, &PL_sv_undef); \
    } else { \
        sv_setref_pv(sv, class, (void *) obj); \
    }


typedef CryptoPP::HashTransformation     CryptoPPHashTransformation;
typedef CryptoPP::RandomNumberGenerator     CryptoPPRNG;
typedef CryptoPP::PK_Signer  CryptoPPPKSigner;

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::HashTransformation

CryptoPPHashTransformation*
Crypt::Cryptopp::HashTransformation::new(const char * type)
CODE:
    CryptoPPHashTransformation* self;
    if (!strcmp(type, "SHA1")) {
        self = new CryptoPP::SHA1();
    } else if (!strcmp(type, "SHA256")) {
        self = new CryptoPP::SHA256();
    } else if (!strcmp(type, "SHA384")) {
        self = new CryptoPP::SHA384();
    } else if (!strcmp(type, "SHA512")) {
        self = new CryptoPP::SHA512();
    } else if (!strcmp(type, "RIPEMD160")) {
        self = new CryptoPP::RIPEMD160();
    } else if (!strcmp(type, "RIPEMD320")) {
        self = new CryptoPP::RIPEMD320();
    } else if (!strcmp(type, "RIPEMD128")) {
        self = new CryptoPP::RIPEMD128();
    } else if (!strcmp(type, "RIPEMD256")) {
        self = new CryptoPP::RIPEMD256();
    } else if (!strcmp(type, "Whirlpool")) {
        self = new CryptoPP::Whirlpool();
        /*
         *  following module doesn't works.
         *  } else if (!strcmp(type, "SHA224")) {
         *      self = new CryptoPP::SHA224();
         */
    } else if (!strcmp(type, "Tiger")) {
        self = new CryptoPP::Tiger();
    } else if (!strcmp(type, "CRC32")) {
        self = new CryptoPP::CRC32();
    } else if (!strcmp(type, "Adler32")) {
        self = new CryptoPP::Adler32();
    } else if (!strcmp(type, "MD2")) {
        self = new CryptoPP::MD2();
    } else if (!strcmp(type, "MD4")) {
        self = new CryptoPP::MD4();
    } else if (!strcmp(type, "MD5")) {
        self = new CryptoPP::MD5();
    } else {
        croak("unknown hash-transformation algorithm");
    }
    assert(self);
    RETVAL = self;
OUTPUT:
    RETVAL

void
update(self, SV*src)
    CryptoPPHashTransformation* self;
CODE:
    STRLEN len;
    char * str = SvPV(src, len);
    self->Update((const byte*)str, len);

SV*
final(self)
    CryptoPPHashTransformation* self;
CODE:
    byte* digest;
    Newx(digest, (self)->DigestSize(), byte);
    (self)->Final(digest);
    SV *sv = newSVpv((const char*)digest, (self)->DigestSize());
    Safefree(digest);
    RETVAL = sv;
OUTPUT:
    RETVAL

void
DESTROY(CryptoPPHashTransformation* self)
CODE:
    delete self;

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::RandomNumberGenerator

CryptoPPRNG*
Crypt::Cryptopp::RandomNumberGenerator::new(const char * type)
CODE:
    CryptoPPRNG* self;
    if (!strcmp(type, "BlockingRng")) {
        self = new CryptoPP::BlockingRng();
    } else if (!strcmp(type, "NonblockingRng")) {
        self = new CryptoPP::NonblockingRng();
    } else {
        croak("unknown random number generator algorithm");
    }
    assert(self);
    RETVAL = self;
OUTPUT:
    RETVAL

U8
generate_byte(CryptoPPRNG* self)
CODE:
    RETVAL = self->GenerateByte();
OUTPUT:
    RETVAL

U32
generate_word32(CryptoPPRNG* self)
CODE:
    RETVAL = self->GenerateWord32();
OUTPUT:
    RETVAL

const char *
algorithm_name(CryptoPPRNG* self)
CODE:
    RETVAL = self->AlgorithmName().c_str();
OUTPUT:
    RETVAL

void
DESTROY(CryptoPPRNG* self)
CODE:
    delete self;

