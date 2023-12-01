#include "Setting.h"
#include "FPJson.h"
#include "FPLog.h"
#include "FileSystemUtil.h"
#include "ServerECCKeyManager.h"

using namespace fpnn;

bool ServerECCKeyManager::load(const char* proto, std::unordered_map<std::string, ECCKeyExchangePtr>& newExchanges)
{
	std::vector<std::string> priorFolderKeys{ std::string("FPNN.server.").append(proto).append(".security.ecdh.keysListFile"), "FPNN.server.security.ecdh.keysListFile"};
	std::string keysListPath = Setting::getString(priorFolderKeys);

	if (keysListPath.empty())
		return true;

	std::string keysListContent;
	if (FileSystemUtil::readFileContent(keysListPath, keysListContent) == false)
	{
		LOG_ERROR("Read %s security keys list file %s failed.", proto, keysListPath.c_str());
		return false;
	}

	JsonPtr keysList;
	try {
		keysList = Json::parse(keysListContent.c_str());
	}
	catch (const FpnnError &e) 
	{
		LOG_ERROR("Parse JSON format for %s keys list file %s failed. Info: %s", proto, keysListPath.c_str(), e.what());
		return false;
	}

	std::string keysListFolder;
	{
		std::size_t pos = keysListPath.find_last_of("/\\");
		if(pos != std::string::npos)
			keysListFolder = keysListPath.substr(0, pos+1);
	}

	const std::map<std::string, JsonPtr> * const keysDict = keysList->getDict();
	for (const auto& jsonPair: *keysDict)
	{
		std::string keyId = jsonPair.first;
		JsonPtr keyInfo = jsonPair.second;

		if (keyInfo->getBool("enable", true))
		{
			std::string curve = keyInfo->getString("curve");
			std::string keyPath = keyInfo->getString("privateKey");

			if (curve.empty())
			{
				LOG_ERROR("Config error! Curve for %s key '%s' is empty.", proto, keyId.c_str());
				continue;
			}

			if (keyPath.empty())
			{
				LOG_ERROR("Config error! Key path for %s key '%s' is empty.", proto, keyId.c_str());
				continue;
			}

			if (keyPath[0] != '/' && keyPath[0] != '\\')
				keyPath = keysListFolder + keyPath;

			std::string privateKey;
			if (FileSystemUtil::readFileContent(keyPath, privateKey) == false)
			{
				LOG_ERROR("Read %s private key file %s for key '%s' failed.", proto, keyPath.c_str(), keyId.c_str());
				continue;
			}

			ECCKeyExchangePtr keyExchange(new ECCKeyExchange);
			if (keyExchange->init(curve, privateKey) == false)
			{
				LOG_ERROR("Init %s key '%s' failed.", proto, keyId.c_str());
				continue;
			}

			newExchanges[keyId] = keyExchange;
		}
	}

	if (newExchanges.find("") == newExchanges.end())
		initAnonymousKey(proto, newExchanges);

	return true;
}
void ServerECCKeyManager::initAnonymousKey(const char* proto, std::unordered_map<std::string, ECCKeyExchangePtr>& newExchanges)
{
	std::vector<std::string> priorCurveKeys{ std::string("FPNN.server.").append(proto).append(".security.ecdh.curve"), "FPNN.server.security.ecdh.curve"};
	std::vector<std::string> priorFileKeys{ std::string("FPNN.server.").append(proto).append(".security.ecdh.privateKey"), "FPNN.server.security.ecdh.privateKey"};

	std::string curve = Setting::getString(priorCurveKeys);
	std::string file = Setting::getString(priorFileKeys);

	if (file.empty())
	{
		if (curve.empty())
			return;

		LOG_ERROR("Config error! Curve for %s global anonymous ECDH is configured, but private key is unconfigured.", proto);
		return;
	}

	if (curve.empty())
	{
		LOG_ERROR("Config error! Private key for %s global anonymous ECDH is configured, but curve is unconfigured.", proto);
		return;
	}

	std::string privateKey;
	if (FileSystemUtil::readFileContent(file, privateKey) == false)
	{
		LOG_ERROR("Read private key file %s for %s global anonymous ECDH failed.", file.c_str(), proto);
		return;
	}

	ECCKeyExchangePtr anonymousExchange(new ECCKeyExchange);
	if (anonymousExchange->init(curve, privateKey) == false)
	{
		LOG_ERROR("Init %s anonymous key failed.", proto);
		return;
	}

	newExchanges[""] = anonymousExchange;
}

bool ServerECCKeyManager::addKeyExchange(const std::string& curve, const std::string& privateKey, const std::string& keyId)
{
	WKeeper keeper(&_rwLocker);
	if (_exchanges.find(keyId) == _exchanges.end())
	{
		ECCKeyExchangePtr keyExchange(new ECCKeyExchange);
		if (keyExchange->init(curve, privateKey))
		{
			_exchanges[keyId] = keyExchange;
			return true;
		}

		LOG_ERROR("Add key '%s' exchange failed. Reason: init error.", keyId.c_str());
		return false;
	}

	LOG_ERROR("Add key '%s' exchange failed. Reason: key has existed.", keyId.c_str());
	return false;
}

ServerECCKeyManagerPtr ServerECCKeyManager::init(const char* proto)
{
	ServerECCKeyManagerPtr keyManager(new ServerECCKeyManager);
	if (keyManager->load(proto, keyManager->_exchanges))
		return keyManager;
	else
	{
		LOG_ERROR("Create ServerECCKeyManager for %s failed.", proto);
		return nullptr;
	}
}

bool ServerECCKeyManager::calcKey(uint8_t* key, uint8_t* iv, int keylen, const std::string& peerPublicKey, const std::string& keyId)
{
	RKeeper keeper(&_rwLocker);
	auto it = _exchanges.find(keyId);
	if (it != _exchanges.end())
	{
		return it->second->calcKey(key, iv, keylen, peerPublicKey);
	}

	LOG_ERROR("Cannot find encryption key %s.", keyId.c_str());
	return false;
}

bool ServerECCKeyManager::reload(const char* proto)
{
	std::unordered_map<std::string, ECCKeyExchangePtr> newExchanges;
	if (load(proto, newExchanges))
	{
		WKeeper keeper(&_rwLocker);
		_exchanges.swap(newExchanges);
		return true;
	}
	return false;
}
