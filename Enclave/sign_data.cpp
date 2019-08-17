#include "sign_data.h"
#include "private_key.h"

void SignData(char* buf, size_t len) {
	std::string priv = "privbtKg4aP3j2DTnh5ux4uqhEymouK67qjV9nbrTLNT4yAUNmP1ZcqF";
	std::string data(buf, len);
	buchain::PrivateKey priv_key(priv);
	std::string public_key = priv_key.GetEncPublicKey();
	std::string sign_data = utils::String::BinToHexString(priv_key.Sign(utils::String::HexStringToBin(data)));

	ocall_handle_pub_key(public_key.c_str());

	ocall_handle_signed_data(sign_data.c_str());
}

