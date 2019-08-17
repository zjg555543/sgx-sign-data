
#include <string.h>

#include "sign_data.h"

void sign_tx_blob(char* buf, size_t len) {
    //std::string input_str(buf, len);
    

    SignData(buf, len);

	//std::string priv = "privbtKg4aP3j2DTnh5ux4uqhEymouK67qjV9nbrTLNT4yAUNmP1ZcqF";
	//std::string data(buf, len);
	//buchain::PrivateKey priv_key(priv);
	//std::string public_key = priv_key.GetEncPublicKey();
	//std::string sign_data = utils::String::BinToHexString(priv_key.Sign(utils::String::HexStringToBin(data)));
}

int sign_data(){
    ocall_print("Processing random number generation...\n");
    return 42;
}

void ecall_repeat_ocalls(unsigned long nrepeats, int use_switchless) {
    sgx_status_t(*ocall_fn)(void) = use_switchless ? ocall_empty_switchless : ocall_empty;
    while (nrepeats--) {
        ocall_fn();
    }
}

void ecall_empty(void) {}
void ecall_empty_switchless(void) {}
