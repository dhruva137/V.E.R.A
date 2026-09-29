#include <openssl/ec.h>
#include <openssl/obj_mac.h>

EC_KEY *make(void) {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
