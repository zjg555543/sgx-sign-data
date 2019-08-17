
#include <string.h>

#include "sign_data.h"

void sign_tx_blob(char* buf, size_t len) {
    SignData(buf, len);
}