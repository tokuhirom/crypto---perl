#include <crypto++/sha.h>
#include <crypto++/tiger.h>
#include <crypto++/crc.h>
#include <crypto++/adler32.h>

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
typedef CryptoPP::SHA1     CryptoPPSHA1;
typedef CryptoPP::Tiger    CryptoPPTiger;
typedef CryptoPP::CRC32    CryptoPPCRC32;
typedef CryptoPP::Adler32  CryptoPPAdler32;

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::HashTransformation

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

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::SHA1

PROTOTYPES: ENABLE

CryptoPPSHA1*
Crypt::Cryptopp::SHA1::new()
CODE:
    CryptoPPSHA1 *obj = new CryptoPP::SHA1();
    assert(obj);
    RETVAL = obj;
OUTPUT:
    RETVAL

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::Tiger

PROTOTYPES: DISABLE

CryptoPPTiger*
Crypt::Cryptopp::Tiger::new()
CODE:
    CryptoPPTiger *obj = new CryptoPP::Tiger();
    RETVAL = obj;
OUTPUT:
    RETVAL

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::CRC32

CryptoPPCRC32*
Crypt::Cryptopp::CRC32::new()
CODE:
    CryptoPPCRC32 *obj = new CryptoPP::CRC32();
    RETVAL = obj;
OUTPUT:
    RETVAL

MODULE = Crypt::Cryptopp  PACKAGE = Crypt::Cryptopp::Adler32

CryptoPPAdler32*
Crypt::Cryptopp::Adler32::new()
CODE:
    CryptoPPAdler32 *obj = new CryptoPP::Adler32();
    RETVAL = obj;
OUTPUT:
    RETVAL

