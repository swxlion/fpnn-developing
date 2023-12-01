#ifndef FPNN_Server_ECC_Key_Manager_h
#define FPNN_Server_ECC_Key_Manager_h

#include <unordered_map>
#include <memory>
#include <string>
#include "RWLocker.hpp"
#include "KeyExchange.h"

namespace fpnn
{
	class ServerECCKeyManager;

	typedef std::shared_ptr<ECCKeyExchange> ECCKeyExchangePtr;
	typedef std::shared_ptr<ServerECCKeyManager> ServerECCKeyManagerPtr;

	class ServerECCKeyManager
	{
		RWLocker _rwLocker;
		std::unordered_map<std::string, ECCKeyExchangePtr> _exchanges;

	private:
		bool load(const char* proto, std::unordered_map<std::string, ECCKeyExchangePtr>& newExchanges);
		void initAnonymousKey(const char* proto, std::unordered_map<std::string, ECCKeyExchangePtr>& newExchanges);

	public:
		bool reload(const char* proto);

		/*
			key: OUT. Key buffer length is equal to keylen.
			iv: OUT. iv buffer length is 16 bytes.
			keylen: IN. 16 or  32.
			peerPublicKey: IN.
			keyId: IN.
		*/
		bool calcKey(uint8_t* key, uint8_t* iv, int keylen, const std::string& peerPublicKey, const std::string& keyId);

		/* Compatible with older versions. Please using configuration items to init it as much as possible. */
		bool addKeyExchange(const std::string& curve, const std::string& privateKey, const std::string& keyId);

	public:
		static ServerECCKeyManagerPtr init(const char* proto);
	};
}

#endif
