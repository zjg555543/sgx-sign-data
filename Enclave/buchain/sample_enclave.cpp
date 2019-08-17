#include "sign_data.h"

void SignTxBlob(char* buf, size_t len) {
	SignData(buf, len);
}
