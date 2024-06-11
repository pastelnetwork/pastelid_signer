I have a digital signature called a pastelid which is an ed448 private key stored in a libsodium SecureContainer file with a passphrase. It's part of a larger application called pasteld that uses RPC methods. The problem is that I'm making another app on top of pasteld that makes a large number of sign/verify calls using the pastelid, and it's slowing down my application dramatically because pasteld can't handle the RPC volume. So I want to make a small standalone Rust program that simply takes the secure container file path and the passphrase string (which it can get from a small config text file) and exposes the sign/verify functions locally without having to go through the pasteld RPC. Then I want to expose the rust functions as a python package using PyO3/maturin. Before we start, let me show you the relevant C++ code from pasteld for dealing with the secure container, because it is absolutely critical that we match this original code in all respects for our new rust program to work correctly:


src/pastelid/secure_container.h
```
#pragma once
// Copyright (c) 2018-2024 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <fstream>

#include <utils/enum_util.h>
#include <utils/vector_types.h>
#include <support/allocators/secure.h>

#include <json/json.hpp>
#include <sodium.h>

namespace secure_container
{

constexpr uint16_t SECURE_CONTAINER_VERSION = 1;
constexpr auto SECURE_CONTAINER_ENCRYPTION = "xchacha20-poly1305";
// Pastel secure container prefix - used to detect new container
constexpr auto SECURE_CONTAINER_PREFIX = "PastelSecureContainer";

/**
 * List of possible secure item types in the secure container.
 */
enum class SECURE_ITEM_TYPE : uint8_t
{
    not_defined = 0,
    pkey_ed448 = 1,    // private key ed448
    pkey_legroast = 2, // LegRoast private key
    wallet = 3,        // wallet.dat
    COUNT              // +1
};

/**
 * List of possible secure item type names in the secure container.
 */
static constexpr const char* SECURE_ITEM_TYPE_NAMES[] =
    {
    "not defined",
    "pkey_ed448",
    "pkey_legroast",
    "wallet"
};

/**
 * List of possible public item types in the secure container.
 */
enum class PUBLIC_ITEM_TYPE : uint8_t {
    not_defined = 0,
    pubkey_legroast = 1, // LegRoast public key
    COUNT                
};

/**
 * List of possible public item type names in the secure container.
 */
static constexpr const char* PUBLIC_ITEM_TYPE_NAMES[] =
    {
    "not defined",
    "pubkey_legroast"
};

/**
 * Get secure item type string by type.
 * 
 * \param type - secure item type
 * \return secure item type name
 */
inline const char* GetSecureItemTypeName(const SECURE_ITEM_TYPE type)
{
    return SECURE_ITEM_TYPE_NAMES[to_integral_type<SECURE_ITEM_TYPE>(type)];
}

/**
 * Get public item type string by type.
 * 
 * \param type - public item type
 * \return public item type name
 */
inline const char* GetPublicItemTypeName(const PUBLIC_ITEM_TYPE type)
{
    return PUBLIC_ITEM_TYPE_NAMES[to_integral_type<PUBLIC_ITEM_TYPE>(type)];
}

/**
 * Get SECURE_ITEM_TYPE by name.
 * 
 * \param sType - secure item type name
 * \return - secure item type
 */
inline SECURE_ITEM_TYPE GetSecureItemTypeByName(const std::string& sType)
{
    SECURE_ITEM_TYPE ItemType = SECURE_ITEM_TYPE::not_defined;
    for (auto i = to_integral_type<SECURE_ITEM_TYPE>(SECURE_ITEM_TYPE::not_defined); 
            i < to_integral_type<SECURE_ITEM_TYPE>(SECURE_ITEM_TYPE::COUNT); ++i)
    {
        if (sType.compare(SECURE_ITEM_TYPE_NAMES[i]) == 0)
        {
            ItemType = static_cast<SECURE_ITEM_TYPE>(i);
            break;
        }
    }
    return ItemType;
}

/**
 * Get PUBLIC_ITEM_TYPE by name.
 * 
 * \param sType - public item type name
 * \return - public item type
 */
inline PUBLIC_ITEM_TYPE GetPublicItemTypeByName(const std::string& sType)
{
    PUBLIC_ITEM_TYPE ItemType = PUBLIC_ITEM_TYPE::not_defined;
    for (auto i = to_integral_type<PUBLIC_ITEM_TYPE>(PUBLIC_ITEM_TYPE::not_defined);
         i < to_integral_type<PUBLIC_ITEM_TYPE>(PUBLIC_ITEM_TYPE::COUNT); ++i)
    {
        if (sType.compare(PUBLIC_ITEM_TYPE_NAMES[i]) == 0)
        {
            ItemType = static_cast<PUBLIC_ITEM_TYPE>(i);
            break;
        }
    }
    return ItemType;
}

class ISecureDataHandler
{
public:
    virtual ~ISecureDataHandler() {}

    virtual bool GetSecureData(nlohmann::json::binary_t& data) const noexcept = 0;
    virtual void CleanupSecureData() = 0;
};

/**
 * Secure container used for storing public/private keys and other secure info.
 * 
 * Secure container has binary format:
 *     PastelSecureContainer(public_items_header)(public_items_msgpack)(secure_items_msgpack)
 * 
 * 
 * public_items_header:
 *     msgpack_public_items_size(datatype: uint64_t in network byte order) public_items_hash (256-bit)
 * 
 * json structure for public items, stored as msgpack:
 * {
 *    "version":1,
 *    "public_items": [
 *      {
 *          "type":"item_type_name",
 *          "data": binary_t
 *      },
 *      {
 *          "type":"item_type_name",
 *          "data": binary_t
 *      }
 *    ]
 * }
 *
 * json structure for secure items, stored as msgpack:
 * {
 *     "version":1,
 *     "timestamp": int64_t,
 *     "encryption": "xchacha20-poly1305",
 *     "secure_items": [
 *         {
 *             "type":"secure_item_type_name",
 *             "nonce": binary_t,
 *             "data": binary_t
 *         },
 *         {
 *             "type":"secure_item_type_name",
 *             "nonce": binary_t,
 *             "data": binary_t
 *         }
 *     ]
 * }
 */
class CSecureContainer
{
public:
    /*
    * secure item structure
    */
    using secure_item_t = struct _secure_item_t
    {
        _secure_item_t() : 
            type(SECURE_ITEM_TYPE::not_defined),
            pHandler(nullptr)
        {}
        _secure_item_t(const SECURE_ITEM_TYPE atype, const nlohmann::json::binary_t& adata, ISecureDataHandler* pDataHandler) : 
            type(atype),
            data(adata),
            pHandler(pDataHandler)
        {}

        void cleanup()
        {
            type = SECURE_ITEM_TYPE::not_defined;
            memory_cleanse(nonce.data(), nonce.size());
            memory_cleanse(data.data(), data.size());
            pHandler = nullptr;
        }

        SECURE_ITEM_TYPE type;
        nlohmann::json::binary_t nonce; // public nonce used to encrypt the data
        nlohmann::json::binary_t data;  // secure item data
        ISecureDataHandler* pHandler;
    };

    /*
    * public item structure
    */
    using public_item_t = struct _public_item_t
    {
        _public_item_t() : 
            type(PUBLIC_ITEM_TYPE::not_defined)
        {}
        _public_item_t(const PUBLIC_ITEM_TYPE atype, nlohmann::json::binary_t&& adata) : 
            type(atype),
            data(std::move(adata))
        {}

        PUBLIC_ITEM_TYPE type;
        nlohmann::json::binary_t data; // public item data
    };

    CSecureContainer() : 
        m_nVersion(SECURE_CONTAINER_VERSION),
        m_nTimestamp(-1)
    {}

    // clear the container
    void clear() noexcept;
    // add secure item to the container (data in a string)
    void add_secure_item_string(const SECURE_ITEM_TYPE type, const std::string& sData) noexcept;
    // add secure item to the container (data in a byte vector)
    void add_secure_item_vector(const SECURE_ITEM_TYPE type, const v_uint8& vData) noexcept;
    void add_secure_item_vector(const SECURE_ITEM_TYPE type, v_uint8&& vData) noexcept;
    // add secure item to the container(handler interface to get data)
    void add_secure_item_handler(const SECURE_ITEM_TYPE type, ISecureDataHandler* pHandler) noexcept;
    // add public item to the container
    void add_public_item(const PUBLIC_ITEM_TYPE type, const std::string& sData) noexcept;
    // encrypt and write container to file as a msgpack
    bool write_to_file(const std::string& sFilePath, SecureString&& sPassphrase);
    // read from secure container file encrypted secure data as a msgpack and decrypt
    bool read_from_file(const std::string& sFilePath, const SecureString& sPassphrase);
    // change passphrase that was used to encrypt the secure container
    bool change_passphrase(const std::string& sFilePath, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase);
    // validate passphrase from secure container
    bool is_valid_passphrase(const std::string& sFilePath, const SecureString& sPassphrase) noexcept;
    // read from secure container file public data as a msgpack
    bool read_public_from_file(std::string &error, const std::string& sFilePath);
    // Get public data (byte vector) from the container by type
    bool get_public_data_vector(const PUBLIC_ITEM_TYPE type, v_uint8& data) const noexcept;
    bool get_public_data(const PUBLIC_ITEM_TYPE type, std::string &sData) const noexcept;
    // Extract secure data from the container by type (returns byte vector)
    v_uint8 extract_secure_data(const SECURE_ITEM_TYPE type);
    // Extract secure data from the container by type (returns string)
    std::string extract_secure_data_string(const SECURE_ITEM_TYPE type);

private:
    static constexpr size_t PWKEY_BUFSUZE = crypto_box_SEEDBYTES;

    // header
    uint16_t m_nVersion;                // container version
    int64_t m_nTimestamp;               // time stamp
    std::string m_sEncryptionAlgorithm; // encryption algorithm

    // vector of public items
    std::vector<public_item_t> m_vPublicItems;
    // vector of secure items
    std::vector<secure_item_t> m_vSecureItems;

    auto find_secure_item(const SECURE_ITEM_TYPE type) noexcept;
    auto find_public_item(const PUBLIC_ITEM_TYPE type) const noexcept;
    bool read_public_items_ex(std::ifstream& fs, uint64_t& nDataSize);
};

    class secure_container_exception : public std::runtime_error 
    {
    public:
        explicit secure_container_exception(const std::string &what) : std::runtime_error(what) { }
    };

} // namespace secure_container

/*
* Helper autoclass to allocate/free sodium buffer.
*/
class CSodiumAutoBuf
{
public:
    CSodiumAutoBuf() : 
        p(nullptr)
    {}
    ~CSodiumAutoBuf()
    {
        free();
    }
    bool allocate(const size_t nSize)
    {
        free();
        p = static_cast<unsigned char *>(sodium_malloc(nSize));
        return p != nullptr;
    }
    void free()
    {
        if (p)
            sodium_free(p);
    }

    unsigned char* p;
};
```


src/pastelid/secure_container.cpp
```
// Copyright (c) 2018-2024 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <algorithm>

#include <utils/tinyformat.h>
#include <utils/vector_types.h>
#include <pastelid/pastel_key.h>
#include <pastelid/secure_container.h>
#include <compat/endian.h>
#include <hash.h>

using namespace std;
using namespace secure_container;

/**
 * Add secure item to the container (data in a string).
 * 
 * \param type - item type
 * \param sData - data string to encrypt
 */
void CSecureContainer::add_secure_item_string(const SECURE_ITEM_TYPE type, const std::string& sData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(move(string_to_vector(sData))), nullptr);
}

/**
 * Add secure item to the container (data in a byte vector).
 * 
 * \param type - item type
 * \param vData - data in a byte vector to encrypt
 */
void CSecureContainer::add_secure_item_vector(const SECURE_ITEM_TYPE type, const v_uint8& vData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(vData), nullptr);
}

void CSecureContainer::add_secure_item_vector(const SECURE_ITEM_TYPE type, v_uint8&& vData) noexcept
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(move(vData)), nullptr);
}

/**
 * Add secure item to the container (handler interface to get data).
 * 
 * \param type - item type
 * \param sData - data string to encrypt
 * \param pHandler - interface to set/get secure data for the item
 */
void CSecureContainer::add_secure_item_handler(const SECURE_ITEM_TYPE type, ISecureDataHandler* pHandler) noexcept 
{
    m_vSecureItems.emplace_back(type, nlohmann::json::binary_t(), pHandler);
}

/**
 * Add public item to the secure container.
 * 
 * \param type - public item type
 * \param sData - public item data
 */
void CSecureContainer::add_public_item(const PUBLIC_ITEM_TYPE type, const std::string& sData) noexcept
{
     m_vPublicItems.emplace_back(type, move(string_to_vector(sData)));
}

/**
 * Encrypt and save secure container to the file.
 * Throws std::runtime_error exception in case of failure.
 * 
 * \param sFilePath - secure container absolute file path
 * \param sPassphrase - passphrase in clear text to use for encryption
 * \return true if file was successfully written
 */
bool CSecureContainer::write_to_file(const string& sFilePath, SecureString&& sPassphrase)
{
    using json = nlohmann::ordered_json;

    ofstream fs(sFilePath, ios::out | ios::binary);
    if (!fs)
        throw runtime_error(strprintf("Cannot open file [%s] to write the secure container", sFilePath.c_str()));

    json jItems;
    // generate json for the public items
    json jPublic =
    {
        { "version", SECURE_CONTAINER_VERSION }
    };
    size_t nJsonPublicSize = 20; // used to estimate size of the json with public items
    
    for (const auto& item: m_vPublicItems)
    {
        const auto szTypeName = GetPublicItemTypeName(item.type);
        jItems.push_back(
            {
                { "type", szTypeName },
                { "data", item.data }
            });
        nJsonPublicSize += 25 + strlen(szTypeName) + item.data.size();
    }
    jPublic.emplace("public_items", move(jItems));
    jItems.clear();

    // generate a json header for the secure items
    m_nTimestamp = time(nullptr);
    json jSecure =
    {
        { "version", SECURE_CONTAINER_VERSION },
        { "timestamp", m_nTimestamp },
        { "encryption", SECURE_CONTAINER_ENCRYPTION }
    };
    size_t nJsonSecureSize = 200; // used to estimate size of the json with secure items
    CSodiumAutoBuf pw;
    // allocate secure memory for the key, buffer is reused for all secure items
    if (!pw.allocate(PWKEY_BUFSUZE))
        throw runtime_error(strprintf("Failed to allocate memory (%zu bytes)", PWKEY_BUFSUZE));
    // encryption buffer is reused for all messages
    json::binary_t encrypted_data;
    for (auto& item : m_vSecureItems)
    {
        // generate nonce
        item.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(item.nonce.data(), item.nonce.size());
        // derive key from the passphrase
        if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
            sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
        {
            throw runtime_error(strprintf("Failed to generate encryption key for '%s'", GetSecureItemTypeName(item.type)));
        }
        // if data handler is defined -> use it to get secure data
        if (item.pHandler)
        {
            if (!item.pHandler->GetSecureData(item.data))
                throw runtime_error(strprintf("Failed to get '%s' data", GetSecureItemTypeName(item.type)));
            // possibility for caller to cleanup data
            item.pHandler->CleanupSecureData();
        }
        // encrypt data using XChaCha20-Poly1305 construction
        unsigned long long nEncSize = 0;
        encrypted_data.resize(item.data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted_data.data(), &nEncSize,
                                                       item.data.data(), item.data.size(), nullptr, 0, nullptr, item.nonce.data(), pw.p) != 0)
            throw runtime_error(strprintf("Failed to encrypt '%s' data", GetSecureItemTypeName(item.type)));
        const auto szTypeName = GetSecureItemTypeName(item.type);
        const size_t nEncryptedDataSize = encrypted_data.size();
        const size_t nItemNonceSize = item.nonce.size();
        jItems.push_back({
            {"type", szTypeName},
            {"nonce", move(item.nonce)},
            {"data", move(encrypted_data)}
        });
        nJsonSecureSize += 50 + strlen(szTypeName) + nItemNonceSize + nEncryptedDataSize;
    }
    jSecure.emplace("secure_items", move(jItems));

    // serialize as a msgpack to file
    fs.write(SECURE_CONTAINER_PREFIX, std::char_traits<char>::length(SECURE_CONTAINER_PREFIX));
    v_uint8 vOut;
    const auto nMsgPackReserve = std::max(nJsonPublicSize, nJsonSecureSize);
    vOut.reserve(nMsgPackReserve);
    // write json for public items to the file serialized into msgpack format
    json::to_msgpack(jPublic, vOut);
    jPublic.clear();
    // write msgpack size in network byte order (big endian)
    const uint64_t nMsgPackSize = htobe64(vOut.size());
    fs.write(reinterpret_cast<const char*>(&nMsgPackSize), sizeof(nMsgPackSize));
    // calculate and write hash of the msgpack
    const auto hash = Hash(vOut.cbegin(), vOut.cend());
    hash.Serialize(fs);
    // write public items in msgpack format
    fs.write(reinterpret_cast<const char*>(vOut.data()), vOut.size());
    vOut.clear();

    // write json for secure items to the file serialized into msgpack format
    json::to_msgpack(jSecure, vOut);
    jSecure.clear();
    fs.write(reinterpret_cast<const char*>(vOut.data()), vOut.size());
    return true;
}

/**
 * Change passphrase that was used to encrypt the secure container.
 * 
 * \param sFilePath - secure container absolute file path
 * \param sOldPassphrase - old passphrase used to encrypt the secure container
 * \param sNewPassphrase - new passphrase (should not be empty)
 * \return true if successfully changed passphrase and encrypted secure container
 *         throws std::runtime_error in case of any error
 */
bool CSecureContainer::change_passphrase(const std::string& sFilePath, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase)
{
    if (sNewPassphrase.empty())
        return false;
    if (!read_from_file(sFilePath, sOldPassphrase))
    {
        string error;
        // for backward compatibility try to read ed448 private key from PKCS8 encrypted file
        if (!CPastelID::ProcessEd448_PastelKeyFile(error, sFilePath, sOldPassphrase, move(sNewPassphrase)))
            throw runtime_error(error);
        // container is already written with the new passphrase
        return true;
    }
    return write_to_file(sFilePath, move(sNewPassphrase));
}

/**
 * Clear the container.
 * 
 */
void CSecureContainer::clear() noexcept
{
    m_nVersion = 0; // version not defined
    m_nTimestamp = -1;
    m_sEncryptionAlgorithm.clear();
    for (auto& item : m_vSecureItems)
        item.cleanup();
    m_vSecureItems.clear();
    m_vPublicItems.clear();
}

/**
 * Read from secure container header and public items.
 * 
 * \param fs - input file stream
 * \param nDataSize - returns 
 * \return true - if public items were successfully read. In this case current position is fs 
 *                will be set to the beginning of the secure items msgpack.
 *         false - if secure container prefix does not match
 *                throws runtime_error if any error occurred while reading secure container public data
 */
bool CSecureContainer::read_public_items_ex(ifstream& fs, uint64_t& nDataSize)
{
    using json = nlohmann::json;
    bool bRet = false;
    do
    {
        // get file size
        const auto nFileSize = fs.tellg();
        if (nFileSize < 0)
            break;
        nDataSize = static_cast<uint64_t>(nFileSize);
        // read prefix from the file and compare with SECURE_CONTAINER_PREFIX
        constexpr auto nPrefixLength = std::char_traits<char>::length(SECURE_CONTAINER_PREFIX);
        if (nDataSize < nPrefixLength)
            break;
        char szPrefix[nPrefixLength + 1];
        fs.seekg(0);
        fs.read(szPrefix, nPrefixLength);
        if (fs.gcount() != nPrefixLength)
            break;
        szPrefix[nPrefixLength] = 0;
        // check if prefix matches
        if (strcmp(szPrefix, SECURE_CONTAINER_PREFIX) != 0)
            break;
        nDataSize -= nPrefixLength;
        // here we should have two fields:
        // [ size of the public items msgpack in network bytes order - uint64_t, 8-bytes] [ hash of the public items msgpack, uint256, 32-bytes ] 
        if (nDataSize < sizeof(uint64_t) + uint256::SIZE)
            throw runtime_error("No public data found in the secure container");
        uint64_t nMsgPackSize = 0;
        v_uint8 vHash;
        vHash.resize(uint256::SIZE);
        fs.read(reinterpret_cast<char*>(&nMsgPackSize), sizeof(uint64_t))
          .read(reinterpret_cast<char*>(vHash.data()), vHash.size());
        nDataSize -= sizeof(uint64_t) + uint256::SIZE;
        // convert size to host order
        nMsgPackSize = be64toh(nMsgPackSize);
        if (nMsgPackSize > nDataSize)
            throw runtime_error(strprintf("Invalid size [%zu] for the public data in the secure container", nMsgPackSize));
        // read public data from the secure container as msgpack
        v_uint8 v;
        v.resize(nMsgPackSize);
        fs.read(reinterpret_cast<char*>(v.data()), v.size());
        // verify hash
        const auto MsgPackHash = Hash(v.cbegin(), v.cend());
        if (memcmp(&MsgPackHash, vHash.data(), uint256::SIZE) != 0)
            throw runtime_error("Failed to verify public data integrity in the secure container");
        nDataSize -= nMsgPackSize;
        json j = json::from_msgpack(v);
        v.clear();
        // process public items
        string sType;
        for (auto& jItem : j.at("public_items"))
        {
            jItem["type"].get_to(sType);
            public_item_t item;
            item.type = GetPublicItemTypeByName(sType);
            if (item.type == PUBLIC_ITEM_TYPE::not_defined)
                throw runtime_error(strprintf("Public item type '%s' is not supported in the secure container", sType));
            item.data = move(jItem["data"].get_binary());
            m_vPublicItems.push_back(move(item));
        }

        bRet = true;
    } while (false);
    return bRet;
}

/**
 * Read from secure container file public data as a msgpack.
 * 
 * \param error - error message
 * \param sFilePath - container file path
 * \return true if public items were successfully read from the container 
 */
bool CSecureContainer::read_public_from_file(string &error, const string& sFilePath)
{
    clear();

    bool bRet = false;
    try
    {
    	ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
	    fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
	    uint64_t nDataSize = 0;
    	bRet = read_public_items_ex(fs, nDataSize);
    }
    catch (const system_error &ex)
    {
        error = strprintf("Failed to read public items from secure container [%s]. %s", sFilePath, ex.code().message());
    }
    return bRet;
}

/**
 * Read from secure container file public and secure data encoded as a msgpack.
 * Decrypt secure data. Throws std::runtime_error exception in case of failure.
 * 
 * \param sFilePath - container file path
 * \param sPassphrase - passphrase in clear text to use for data decryption
 * \return true if file was successfully read and decrypted
 *         false if file does not contain Pastel secure container
 *         if container data cannot be read or decrypted - throws std::runtime_error
 */
bool CSecureContainer::read_from_file(const string& sFilePath, const SecureString& sPassphrase)
{
    using json = nlohmann::json;
    bool bRet = false;
    try
    {
        do
        {
            clear();

            if (!fs::exists(sFilePath))
                throw runtime_error(strprintf(
                    "Pastel ID [%s] is not stored in this local node",
                    fs::path(sFilePath).filename().string()));
            ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
            fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            v_uint8 v;
            uint64_t nDataSize = 0;
            if (!read_public_items_ex(fs, nDataSize))
                break;
            // read secure container data as json msgpack
            v.resize(nDataSize);
            fs.read(reinterpret_cast<char*>(v.data()), v.size());
            json j = json::from_msgpack(v);
            v.clear();

            // read header
            j.at("version").get_to(m_nVersion);
            j.at("timestamp").get_to(m_nTimestamp);
            j.at("encryption").get_to(m_sEncryptionAlgorithm);
            if (m_sEncryptionAlgorithm.compare(SECURE_CONTAINER_ENCRYPTION) != 0)
                throw runtime_error(strprintf(
                    "Encryption algorithm '%s' is not supported", 
                    m_sEncryptionAlgorithm.c_str()));

            CSodiumAutoBuf pw;
            // allocate secure memory for the key, buffer is reused for all secure items
            if (!pw.allocate(PWKEY_BUFSUZE))
                throw runtime_error(strprintf(
                    "Failed to allocate memory (%zu bytes)", 
                    PWKEY_BUFSUZE));

            // process encrypted items
            // read nonce for each item and use it to derive password key from passphrase and 
            // to decrypt data
            string sType;
            for (auto &jItem : j.at("secure_items"))
            {
                jItem["type"].get_to(sType);
                secure_item_t item;
                item.type = GetSecureItemTypeByName(sType);
                if (item.type == SECURE_ITEM_TYPE::not_defined)
                    throw runtime_error(strprintf("Secure item type '%s' is not supported", sType));
                jItem["nonce"].get_to(item.nonce);
                // encrypted data
                auto& encrypted_data = jItem["data"].get_binary();

                // derive key from the passphrase
                if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
                                  sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
                {
                    throw runtime_error(strprintf("Failed to generate encryption key for the secure item '%s'", GetSecureItemTypeName(item.type)));
                }
                item.data.resize(encrypted_data.size());
                unsigned long long nDecryptedLength = 0;
                if (crypto_aead_xchacha20poly1305_ietf_decrypt(item.data.data(), &nDecryptedLength, nullptr,
                        encrypted_data.data(), encrypted_data.size(), nullptr, 0, item.nonce.data(), pw.p) != 0)
                {
                    throw secure_container_exception(strprintf(
                        "Passphrase is invalid. Failed to decrypt secure item '%s' data", 
                        sType));
                }
                item.data.resize(nDecryptedLength);
                m_vSecureItems.push_back(move(item));
            }
            bRet = true;
        } while (false);
    }
    catch (const std::out_of_range &ex)
    {
        throw runtime_error(strprintf("Pastel secure container file format error. %s", ex.what()));
    }
    catch (const secure_container_exception &ex)
    {
        throw runtime_error(strprintf("%s", ex.what()));
    }
    catch (const std::exception &ex)
    {
        throw runtime_error(strprintf("Failed to read Pastel secure container file [%s]. %s", sFilePath.c_str(), ex.what()));
    }
    return bRet;
}

/**
 * Validate passphrase via SECURE_ITEM_TYPE::pkey_ed448.
 * Decrypt secure data. Does not throws exceptions
 * 
 * \param sFilePath - container file path
 * \param sPassphrase - passphrase in clear text to use for data decryption
 * \return true if password was succesfully validated
 *         false if file does not contain Pastel secure container
 *         if container data cannot be read or decrypted - throws std::runtime_error
 */
bool CSecureContainer::is_valid_passphrase(const string& sFilePath, const SecureString& sPassphrase) noexcept
{
    using json = nlohmann::json;
    bool bRet = false;
    string error;
    try
    {
        do
        {
            clear();

            ifstream fs(sFilePath, ios::in | ios::ate | ios::binary);
            fs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            v_uint8 v;
            uint64_t nDataSize = 0;
            if (!read_public_items_ex(fs, nDataSize))
            {
                error = "Failed to read public items";
                break;
            }
            // read secure container data as json msgpack
            v.resize(nDataSize);
            fs.read(reinterpret_cast<char*>(v.data()), v.size());
            json j = json::from_msgpack(v);
            v.clear();

            // read header
            j.at("version").get_to(m_nVersion);
            j.at("timestamp").get_to(m_nTimestamp);
            j.at("encryption").get_to(m_sEncryptionAlgorithm);
            if (m_sEncryptionAlgorithm.compare(SECURE_CONTAINER_ENCRYPTION) != 0)
            {
                error = strprintf("Encryption algorithm '%s' is not supported", m_sEncryptionAlgorithm.c_str());
                break;
            }

            CSodiumAutoBuf pw;
            // allocate secure memory for the key, buffer is reused for all secure items
            if (!pw.allocate(PWKEY_BUFSUZE))
            {
                error = strprintf("Failed to allocate memory (%zu bytes)", PWKEY_BUFSUZE);
                break;
            }

            // process encrypted items
            // read nonce for each item and use it to derive password key from passphrase and 
            // to decrypt data
            string sType;
            for (auto &jItem : j.at("secure_items"))
            {
                jItem["type"].get_to(sType);
                secure_item_t item;
                item.type = GetSecureItemTypeByName(sType);
                if (item.type == SECURE_ITEM_TYPE::not_defined)
                {
                    error = strprintf("Secure item type '%s' is not supported", sType);
                    break;
                }
                jItem["nonce"].get_to(item.nonce);
                // encrypted data
                auto& encrypted_data = jItem["data"].get_binary();

                // derive key from the passphrase
                if (crypto_pwhash(pw.p, crypto_box_SEEDBYTES,
                                  sPassphrase.c_str(), sPassphrase.length(), item.nonce.data(),
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
                {
                    error = strprintf("Failed to generate encryption key for the secure item '%s'", GetSecureItemTypeName(item.type));
                    break;
                }
                item.data.resize(encrypted_data.size());
                unsigned long long nDecryptedLength = 0;
                if (crypto_aead_xchacha20poly1305_ietf_decrypt(item.data.data(), &nDecryptedLength, nullptr,
                        encrypted_data.data(), encrypted_data.size(), nullptr, 0, item.nonce.data(), pw.p) != 0)
                {
                    error = strprintf("Failed to decrypt secure item '%s' data", sType);
                    break;
                }
                // Only need to read first secure item which has pkey_ed448 type
                if (item.type == SECURE_ITEM_TYPE::pkey_ed448)
                    break;
            }
            if (!error.empty())
                break;
            bRet = true;
        } while (false);
    }
    catch (const std::out_of_range &ex)
    {
        error = strprintf("File format error. %s", ex.what());
    }
    catch (const std::exception &ex)
    {
        error = strprintf("%s", sFilePath.c_str(), ex.what());
    }
    if (!error.empty())
        LogPrintf("Passphrase is invalid. Failed to read the Pastel secure container file [%s]. %s\n", sFilePath, error);
    return bRet;
}

/**
 * Find secure item in the container by type.
 * 
 * \param type - secure item type to find
 * \return 
 */
auto CSecureContainer::find_secure_item(const SECURE_ITEM_TYPE type) noexcept
{
    return find_if(m_vSecureItems.begin(), m_vSecureItems.end(), [=](const auto& Item) { return Item.type == type; });
}

/**
 * Find public item in the container by type.
 * 
 * \param type - secure item type to find
 * \return 
 */
auto CSecureContainer::find_public_item(const PUBLIC_ITEM_TYPE type) const noexcept
{
    return find_if(m_vPublicItems.cbegin(), m_vPublicItems.cend(), [=](const auto& Item) { return Item.type == type; });
}

/**
 * Get public data (byte vector) from the container by type.
 * 
 * \param type - public item type
 * \param data - public binary data
 * \return true if public item was found in the secure container
 */
bool CSecureContainer::get_public_data_vector(const PUBLIC_ITEM_TYPE type, v_uint8& data) const noexcept
{
    const auto it = find_public_item(type);
    if (it != m_vPublicItems.cend())
    {
        data = it->data;
        return true;
    }
    return false;
}

/**
 * Get public data (string) from the container by type.
 * 
 * \param type - public item type
 * \param sData - public string data
 * \return true if public item was found in the secure container
 */
bool CSecureContainer::get_public_data(const PUBLIC_ITEM_TYPE type, std::string& sData) const noexcept
{
    const auto it = find_public_item(type);
    if (it != m_vPublicItems.cend())
    {
        sData.assign(it->data.cbegin(), it->data.cend());
        return true;
    }
    return false;
}

/**
 * Extract secure data from the container by type (byte vector).
 * 
 * \param type - secure item type
 * \return - secure data in byte vector (moved from storage)
 */
v_uint8 CSecureContainer::extract_secure_data(const SECURE_ITEM_TYPE type)
{
    auto it = find_secure_item(type);
    if (it != m_vSecureItems.end())
        return move(it->data);
    return v_uint8();
}

/**
 * Extract secure data from the container by type (string).
 * 
 * \param type - secure item type
 * \return - secure data (moved from storage)
 */
string CSecureContainer::extract_secure_data_string(const SECURE_ITEM_TYPE type)
{
    auto it = find_secure_item(type);
    string sData;
    if (it != m_vSecureItems.end())
    {
        sData.assign(reinterpret_cast<const char *>(it->data.data()), it->data.size());
        memory_cleanse(it->data.data(), it->data.size());
        it->data.clear();
    }
    return sData;
}
```

src/pastelid/common.h
```
#pragma once
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <iomanip>
#include <sstream>
#include <cmath>

#include <utils/vector_types.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

namespace ed_crypto {

    static constexpr int OK = 1;
    static constexpr auto BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline std::string Base64_Encode(const unsigned char *in, const size_t len) noexcept
    {
        std::string out;
        out.reserve(static_cast<size_t>(ceil(len / 3) * 4));
        int val=0, valb=-6;

        for (size_t i = 0; i < len; i++)
        {
            val = (val << 8) + in[i];
            valb += 8;
            while (valb >= 0)
            {
                out.push_back(BASE64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb>-6) 
            out.push_back(BASE64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4)
            out.push_back('=');
        return out;
    }
	
    inline v_uint8 Base64_Decode(const std::string &in) noexcept
    {
        v_uint8 out;
        out.reserve((in.size() / 4) * 3);

        std::vector<int> T(256,-1);
        for (int i=0; i<64; i++)
            T[BASE64[i]] = i;

        int val=0, valb=-8;
        for (const unsigned char c : in)
        {
            if (T[c] == -1)
                break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0)
            {
                out.push_back( static_cast<unsigned char>((val >> valb) & 0xFF));
                valb-=8;
            }
        }
        return out;
    }

    /**
     * Encode buffer into hex string.
     * 
     * \param in - buffer to encode
     * \param len - buffer length
     * \return hex string 
     */
    inline std::string Hex_Encode(const unsigned char *in, const size_t len)
    {
        std::ostringstream hex_str_str;
        for (size_t i = 0; i < len; i++)
            hex_str_str << std::setfill('0') << std::setw(2) << std::hex << (int) in[i];
        return hex_str_str.str();
    }
	
    inline v_uint8 Hex_Decode(const std::string &in)
    {
        v_uint8 out;
        for (size_t i = 0; i < in.length(); i+=2)
        {
            unsigned int c;
            std::stringstream ss;
            std::string byte = in.substr(i,2);
            ss << byte;
            ss >> std::hex >> c;
            out.push_back(c);
        }
        return out;
    }

    //stream
    class stream {

        struct BioDeleterFunctor {
            void operator()(BIO *buf) {
                BIO_free(buf);
            }
        };

    public:
        using unique_bio_ptr = std::unique_ptr<BIO, BioDeleterFunctor>;

        template <class Bio_method, class Writer>
        static std::string bioToString(Bio_method method, Writer writer)
        {
            auto bio = unique_bio_ptr(BIO_new(method));

            writer(bio.get());
//            if (OK != writer(bio.get()))
//                return std::string();

            BUF_MEM* buffer = nullptr;
            BIO_get_mem_ptr(bio.get(), &buffer);

            if (!buffer || !buffer->data || !buffer->length)
                return std::string();

            return std::string(buffer->data, buffer->length);
        }
    };

    //unsigned char buffer
    class buffer {

        struct BufferDeleterFunctor {
            void operator()(unsigned char *buf) {
                OPENSSL_free(buf);
            }
        };

        using unique_buffer_ptr = std::unique_ptr<unsigned char, BufferDeleterFunctor>;

    public:
        buffer(unsigned char *pbuf, const std::size_t len) : 
            m_buf(pbuf), 
            m_nLength(len)
        {}

        std::string str() const noexcept
        {
            std::string s(reinterpret_cast<char const*>(m_buf.get()), m_nLength);
            return s;
        }

        v_uint8 data() const noexcept
        {
            const auto pBuf = m_buf.get();
            v_uint8 out{pBuf, pBuf + m_nLength};
            return out;
        }

        std::string Base64() noexcept
        {
            return Base64_Encode(m_buf.get(), m_nLength);
        }

        std::string Hex() noexcept
        {
            return Hex_Encode(m_buf.get(), m_nLength);
        }

        std::size_t len() const noexcept { return m_nLength; }
        unsigned char* get() const noexcept { return m_buf.get(); }

    private:
        unique_buffer_ptr m_buf;
        std::size_t m_nLength;
    };

    class crypto_exception : public std::exception
    {
        std::string message;
    public:
        crypto_exception(const std::string &error, const std::string &details, const std::string &func_name)
        {
            std::ostringstream str_str;
            str_str << func_name << " - " << error << ": " << details;

            std::string errStr = stream::bioToString(BIO_s_mem(), [this](BIO* bio)
            {
                return ERR_print_errors(bio);
            });
            str_str << std::endl << "OpenSSL error: " << std::endl << errStr;

            message = str_str.str();
        }

        const char *what() const noexcept override
        {
            return message.c_str();
        }
    };
	
	inline std::string Password_Stretching(const std::string& password)
	{
		unsigned char pout[32] = {};
		
		if (OK != PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()), nullptr, 0, 1000, EVP_sha512(), 32, pout))
			throw crypto_exception("", std::string(), "PKCS5_PBKDF2_HMAC");
		
		std::string out{reinterpret_cast<char*>(pout), 32};
		return out;
	}
}

```

src/pastelid/pastel_key.h
```
#pragma once
// Copyright (c) 2018-2024 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <unordered_map>

#include <utils/fs.h>
#include <utils/vector_types.h>
#include <utils/map_types.h>
#include <support/allocators/secure.h>
#include <legroast.h>

// storage type for pastel ids and associated keys
using pastelid_store_t = mu_strings;

constexpr auto SIGN_ALG_ED448 = "ed448";
constexpr auto SIGN_ALG_LEGROAST = "legroast";

class CPastelID
{
    static constexpr size_t  PASTELID_PUBKEY_SIZE = 57;
    static constexpr uint8_t PASTELID_PREFIX[] = {0xA1, 0xDE};

    static constexpr size_t  LEGROAST_PUBKEY_SIZE = legroast::PK_BYTES;
    static constexpr uint8_t LEGROAST_PREFIX[] = {0x51, 0xDE};

public:
    enum class SIGN_ALGORITHM : int
    {
        not_defined = 0,
        ed448 = 1,
        legroast = 2
    };

    // Generate new Pastel ID(EdDSA448) and LegRoast public / private key pairs.
    static pastelid_store_t CreateNewPastelKeys(SecureString&& passPhrase);
    // Get signing algorithm enum by name.
    static SIGN_ALGORITHM GetAlgorithmByName(const std::string& s);
    // Sign text with the private key associated with PastelID.
    static std::string Sign(const std::string& sText, const std::string& sPastelID, SecureString&& sPassPhrase, 
        const SIGN_ALGORITHM alg = SIGN_ALGORITHM::ed448, const bool fBase64 = false);
    // Verify signature with the public key associated with PastelID.
    static bool Verify(const std::string& sText, const std::string& sSignature, const std::string& sPastelID, 
        const SIGN_ALGORITHM alg = SIGN_ALGORITHM::ed448, const bool fBase64 = false);
    static pastelid_store_t GetStoredPastelIDs(const bool bPastelIdOnly = true, const std::string &sFilterPastelID = std::string(""));
    // Validate passphrase via secure container or pkcs8 format
    static bool isValidPassphrase(const std::string& sPastelId, const SecureString& strKeyPass) noexcept;
    // Change passphrase used to encrypt the secure container
    static bool ChangePassphrase(std::string &error, const std::string& sPastelId, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase);
    // read ed448 private key from PKCS8 file (old format)
    static bool ProcessEd448_PastelKeyFile(std::string& error, const std::string& sFilePath, const SecureString& sOldPassPhrase, SecureString &&sNewPassPhrase);

protected:
    // encode/decode PastelID
    static std::string EncodePastelID(const v_uint8& key);
    static bool DecodePastelID(const std::string& sPastelID, v_uint8& vData);
    // encode/decode LegRoast public key
    static std::string EncodeLegRoastPubKey(const std::string& sPubKey);
    static bool DecodeLegRoastPubKey(const std::string& sLRKey, v_uint8& vData);
    static bool CheckPastelKeysDirectory(fs::path &pathPastelKeys, const bool bCreateDirs = true);

private:
    // get full path for the secure container based on Pastel ID
    static fs::path GetSecureContFilePathEx(const std::string& sPastelID, const bool bCreateDirs = true);
    // get full path for the secure container based on Pastel ID
    static std::string GetSecureContFilePath(const std::string& sPastelID, const bool bCreateDirs = true);
};
```

src/pastelid/pastel_key.cpp
```
// Copyright (c) 2018-2024 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <utils/str_utils.h>
#include <utils/base58.h>
#include <key_io.h>
#include <pastelid/ed.h>
#include <pastelid/secure_container.h>
#include <mnode/mnode-controller.h>
#include <mnode/tickets/pastelid-reg.h>
#include <pastelid/pastel_key.h>

using namespace std;
using namespace legroast;
using namespace ed_crypto;
using namespace secure_container;

/**
* Generate new Pastel ID (EdDSA448) and LegRoast public/private key pairs.
* Create new secure container to store all items associated with Pastel ID.
* 
* \param passPhrase - secure passphrase that will be used to encrypt secure container.
* \return pastelid_store_t map [encoded Pastel ID] -> [encoded LegRoast public key]
*/
pastelid_store_t CPastelID::CreateNewPastelKeys(SecureString&& passPhrase)
{
    pastelid_store_t resultMap;
    try
    {
        // Pastel ID private/public keys (EdDSA448)
        const key_dsa448 key = key_dsa448::generate_key();
        // encode public key with Pastel ID prefix (A1DE), base58 encode + checksum
        string sPastelID = EncodePastelID(key.public_key_raw().data());
        // LegRoast signing keys
        CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
        // generate LegRoast private/public key pair
        LegRoastKey.keygen();
        string sEncodedLegRoastPubKey = EncodeLegRoastPubKey(LegRoastKey.get_public_key());
        // write secure container with both private keys
        CSecureContainer cont;
        cont.add_public_item(PUBLIC_ITEM_TYPE::pubkey_legroast, sEncodedLegRoastPubKey);
        cont.add_secure_item_vector(SECURE_ITEM_TYPE::pkey_ed448, key.private_key_raw().data());
        cont.add_secure_item_vector(SECURE_ITEM_TYPE::pkey_legroast, LegRoastKey.get_private_key());
        cont.write_to_file(GetSecureContFilePath(sPastelID, true), move(passPhrase));

        // populate storage object with encoded PastelID and LegRoast public keys
        resultMap.emplace(move(sPastelID), move(sEncodedLegRoastPubKey));
    } catch (const crypto_exception& ex) {
        throw runtime_error(ex.what());
    }
    return resultMap;
}

/**
* Get signing algorithm enum by name.
* 
* \param s - algorithm (empty string, ed448 or legroast)
* \return enum item
*/
CPastelID::SIGN_ALGORITHM CPastelID::GetAlgorithmByName(const string& s)
{
    SIGN_ALGORITHM alg = SIGN_ALGORITHM::not_defined;
    if (s.empty() || s == SIGN_ALG_ED448)
        alg = SIGN_ALGORITHM::ed448;
    else if (s == SIGN_ALG_LEGROAST)
        alg = SIGN_ALGORITHM::legroast;
    return alg;
}

/**
 * Read ed448 private key from PKCS8 encrypted file.
 * Generate new LegRoast private-public key pair.
 * Create new secure container and delete PKCS8 file.
 * 
 * \return true if new secure container file successfully generated
 */
bool CPastelID::ProcessEd448_PastelKeyFile(string& error, const string& sFilePath, const SecureString& sPassPhrase, SecureString&& sNewPassPhrase)
{
    bool bRet = false;
    try
    {
        CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
        CSecureContainer cont;

        // for backward compatibility read ed448 private key from PKCS8 encrypted file
        // this will throw ed_crypto::crypto_exception in case it can't decrypt file
        const auto key = ed_crypto::key_dsa448::read_private_key_from_PKCS8_file(sFilePath, sPassPhrase.c_str());

        string sED448pkey = key.private_key_raw().str();
        // we don't have LegRoast key in the old PKCS8-file, generate it and replace file with the new secure container
        // generate LegRoast private/public key pair
        LegRoastKey.keygen();
        cont.add_public_item(PUBLIC_ITEM_TYPE::pubkey_legroast, move(EncodeLegRoastPubKey(LegRoastKey.get_public_key())));
        cont.add_secure_item_string(SECURE_ITEM_TYPE::pkey_ed448, sED448pkey);
        cont.add_secure_item_vector(SECURE_ITEM_TYPE::pkey_legroast, move(LegRoastKey.get_private_key()));
        // write new secure container
        bRet = cont.write_to_file(sFilePath, move(sNewPassPhrase));
        if (!bRet)
            error = strprintf("Failed to write secure container file [%s]", sFilePath);
    } catch (const ed_crypto::crypto_exception& ex)
    {
        error = ex.what();
    }
    return bRet;
}

/**
* Sign text with the private key associated with Pastel ID.
* throws runtime_error exception in case of any read/write operations with secure container
* 
* \param sText - text to sign
* \param sPastelID - locally stored Pastel ID (base58-encoded with prefix and checksum)
* \param sPassPhrase - passphrase used to access private keys associated with Pastel ID
* \param alg - algorithm to use for signing (ed448[default] or legroast)
* \param fBase64 - if true, signature should be encoded in base64
* \return signature
*/
string CPastelID::Sign(const string& sText, const string& sPastelID, SecureString&& sPassPhrase, const SIGN_ALGORITHM alg, const bool fBase64)
{
    string sSignature;
    string error;
    try
    {
        const auto sFilePath = GetSecureContFilePath(sPastelID);
        CSecureContainer cont;
        CLegRoast<algorithm::Legendre_Middle> LegRoastKey;
        string sED448pkey;
        // first try to read file as a secure container
        // returns false if file content does not start with secure container prefix
        bool bRead = cont.read_from_file(sFilePath, sPassPhrase);
        if (!bRead)
        {
            // for backward compatibility try to read ed448 private key from PKCS8 encrypted file
            SecureString sPassPhraseNew(sPassPhrase);
            if (!ProcessEd448_PastelKeyFile(error, sFilePath, sPassPhrase, move(sPassPhraseNew)))
                throw runtime_error(error);
            bRead = cont.read_from_file(sFilePath, sPassPhrase);
        }
        if (!bRead)
            throw runtime_error(strprintf("Cannot access secure container '%s'", sFilePath));
        switch (alg)
        {
            case SIGN_ALGORITHM::ed448: {
                sED448pkey = cont.extract_secure_data_string(SECURE_ITEM_TYPE::pkey_ed448);
                const auto key = ed_crypto::key_dsa448::create_from_raw_private(reinterpret_cast<const unsigned char*>(sED448pkey.data()), sED448pkey.size());
                // sign with ed448 key
                ed_crypto::buffer sigBuf = ed_crypto::crypto_sign::sign(sText, key);
                sSignature = fBase64 ? sigBuf.Base64() : sigBuf.str();
            } break;

            case SIGN_ALGORITHM::legroast:
            {
                v_uint8 pkey = cont.extract_secure_data(SECURE_ITEM_TYPE::pkey_legroast);
                if (!LegRoastKey.set_private_key(error, pkey.data(), pkey.size()))
                    throw runtime_error(error);
                if (!LegRoastKey.sign(error, reinterpret_cast<const unsigned char*>(sText.data()), sText.length()))
                    throw runtime_error(strprintf("Failed to sign text message with the LegRoast private key. %s", error));
                sSignature = LegRoastKey.get_signature();
                if (fBase64)
                    sSignature = ed_crypto::Base64_Encode(reinterpret_cast<const unsigned char*>(sSignature.data()), sSignature.length());
            } break;

            default:
                break;
        }
    } catch (const ed_crypto::crypto_exception& ex) {
        throw runtime_error(ex.what());
    }
    return sSignature;
}

/**
* Verify signature with the public key associated with Pastel ID.
* 
* \param sText - text to verify signature for
* \param sSignature - signature in base64 format
* \param sPastelID - Pastel ID (encoded public EdDSA448 key)
* \param alg - algorithm to use for verification (ed448[default] or legroast)
* \param fBase64 - if true signature is base64-encoded
* \return true if signature is correct
*/
bool CPastelID::Verify(const string& sText, const string& sSignature, const string& sPastelID, const SIGN_ALGORITHM alg, const bool fBase64)
{
    bool bRet = false;
    string error;
    try
    {
        switch (alg)
        {
            case SIGN_ALGORITHM::ed448:
            {
                v_uint8 vRawPubKey;
                if (!DecodePastelID(sPastelID, vRawPubKey))
                    return false;
                // use EdDSA448 public key to verify signature
                auto key = ed_crypto::key_dsa448::create_from_raw_public(vRawPubKey.data(), vRawPubKey.size());
                if (fBase64)
                    bRet = ed_crypto::crypto_sign::verify_base64(sText, sSignature, key);
                else
                    bRet = ed_crypto::crypto_sign::verify(sText, sSignature, key);
            } break;

            case SIGN_ALGORITHM::legroast:
            {
                constexpr auto LRERR_PREFIX = "Cannot verify signature with LegRoast algorithm. ";
                string sLegRoastPubKey;
                v_uint8 vLRPubKey;
                CSecureContainer cont;
                const auto sFilePath = GetSecureContFilePath(sPastelID);
                // check if this Pastel ID is stored locally
                // if yes - read LegRoast public key from the secure container (no passphrase needed)
                // if no - lookup ID Registration ticket in the blockchain and get LegRoast pubkey from the ticket
                if (fs::exists(sFilePath))
                {
                    // read public items from the secure container file
                    if (!cont.read_public_from_file(error, sFilePath))
                        throw runtime_error(strprintf("%sLegRoast public key was not found in the secure container associated with Pastel ID [%s]. %s", 
                            LRERR_PREFIX, sPastelID, error));
                    // retrieve encoded LegRoast public key
                    if (!cont.get_public_data(PUBLIC_ITEM_TYPE::pubkey_legroast, sLegRoastPubKey))
                        throw runtime_error(strprintf("%sLegRoast public key associated with the Pastel ID [%s] was not found", LRERR_PREFIX, sPastelID));
                } else {
                    CPastelIDRegTicket regTicket;
                    if (!CPastelIDRegTicket::FindTicketInDb(sPastelID, regTicket))
                        throw runtime_error(strprintf("%sPastel ID [%s] is not stored locally and Pastel ID registration ticket was not found in the blockchain", 
                            LRERR_PREFIX, sPastelID));
                    if (!regTicket.isLegRoastKeyDefined())
                        throw runtime_error(strprintf("%sPastel ID [%s] registration ticket [txid=%s] was found in the blockchain, but LegRoast public key is empty", 
                            LRERR_PREFIX, sPastelID, regTicket.GetTxId()));
                    regTicket.moveLegRoastKey(sLegRoastPubKey);
                }
                // decode base58-encoded LegRoast public key
                string error;
                if (DecodeLegRoastPubKey(sLegRoastPubKey, vLRPubKey))
                {
                    bool bValid = false;
                    // verify signature
                    CLegRoast<algorithm::Legendre_Middle> LegRoast;
                    if (LegRoast.set_public_key(error, vLRPubKey.data(), vLRPubKey.size()))
                    {
	                    if (fBase64)
        	                bValid = LegRoast.set_signature(error, ed_crypto::Base64_Decode(sSignature));
                	    else
	                        bValid = LegRoast.set_signature(error, reinterpret_cast<const unsigned char*>(sSignature.data()), sSignature.size());
                    }
                    if (!bValid)
                    	throw runtime_error(strprintf("Cannot verify signature with LegRoast algorithm. %s", error));
                    bRet = LegRoast.verify(error, reinterpret_cast<const unsigned char*>(sText.data()), sText.size());
                }
            } break;

            default:
                break;
        } // switch
    } catch (const ed_crypto::crypto_exception& ex) {
        throw runtime_error(ex.what());
    }
    return bRet;
}

/**
* Get Pastel IDs stored locally in pastelkeys directory.
* 
* \param bPastelIdOnly - return Pastel IDs only, otherwise returns PastelIDs along with associated keys
*                        read from the secure container
* \param sFilterPastelID - optional parameter, can be used as a filter to retrieve only specific Pastel ID
* \return map of 'Pastel ID' -> associated keys (LegRoast signing public key)
*/
pastelid_store_t CPastelID::GetStoredPastelIDs(const bool bPastelIdOnly, const string& sFilterPastelID)
{
    string error;
    fs::path pathPastelKeys;
    pastelid_store_t resultMap;

    if (!CheckPastelKeysDirectory(pathPastelKeys))
        return resultMap;

        string sPastelID, sLegRoastKey;
        v_uint8 vData;
        for (const auto& p : fs::directory_iterator(pathPastelKeys))
        {
            sPastelID = p.path().filename().string();
            if (!sFilterPastelID.empty() && !str_icmp(sFilterPastelID, sPastelID))
                continue;
            // check if this file name is in fact encoded Pastel ID
            // if not - just skip this file
            if (!DecodePastelID(sPastelID, vData))
                continue;
            sLegRoastKey.clear();
            if (!bPastelIdOnly)
            {
                // read public items from secure container
                // ignore error here -> will return empty LegRoast public key
                CSecureContainer cont;
                if (cont.read_public_from_file(error, p.path().string()))
                    cont.get_public_data(PUBLIC_ITEM_TYPE::pubkey_legroast, sLegRoastKey);
            }
            resultMap.emplace(move(sPastelID), move(sLegRoastKey));
        }
    return resultMap;
}

bool CPastelID::isValidPassphrase(const string& sPastelId, const SecureString& strKeyPass) noexcept
{
    bool bRet = false;
    try {
        // Get pastelkeyfile
        const auto fileObj = GetSecureContFilePathEx(sPastelId);

        if (!fs::exists(fileObj))
            return false;
        secure_container::CSecureContainer cont;
        legroast::CLegRoast<legroast::algorithm::Legendre_Middle> LegRoastKey;
        string sED448pkey;
        // first try to read file as a secure container
        // returns false if file content does not start with secure container prefix
        if (cont.is_valid_passphrase(fileObj.string(), strKeyPass))
            bRet = true;
        else
        {
            //If old pkcs8 format is the format try to read that way
            auto key = ed_crypto::key_dsa448::read_private_key_from_PKCS8_file(fileObj.string(), strKeyPass.c_str());
            sED448pkey = key.private_key_raw().str();
            bRet = true;
        }

    } catch (const exception &ex) {
        LogPrintf("Failed to validate passphrase due to: %s\n", ex.what());
    }
    return bRet;
}

/**
 * Change passphrase used to encrypt the secure container.
 * 
 * \param pastelid - Pastel ID (secure containter file name)
 * \param sOldPassphrase - old passphrase 
 * \param sNewPassphrase - new passphrase
 * \return 
 */
bool CPastelID::ChangePassphrase(std::string &error, const std::string& sPastelId, SecureString&& sOldPassphrase, SecureString&& sNewPassphrase)
{
    bool bRet = false;
    string sError;
    try
    {
        error.clear();
        const string sFilePath = GetSecureContFilePath(sPastelId);
        CSecureContainer cont;
        bRet = cont.change_passphrase(sFilePath, move(sOldPassphrase), move(sNewPassphrase));
    } catch (const exception& ex) {
        sError = ex.what();
    }
    if (!bRet)
        error = strprintf("Cannot change passphrase for the Pastel secure container. %s", sError);
    return bRet;
}

string CPastelID::EncodePastelID(const v_uint8& key)
{
    v_uint8 vData;
    vData.reserve(key.size() + sizeof(PASTELID_PREFIX));
    vData.assign(cbegin(PASTELID_PREFIX), cend(PASTELID_PREFIX));
    vData.insert(vData.end(), key.cbegin(), key.cend());
    string sRet = EncodeBase58Check(vData);
    memory_cleanse(vData.data(), vData.size());
    return sRet;
}

bool CPastelID::DecodePastelID(const string& sPastelID, v_uint8& vData)
{
    if (!DecodeBase58Check(sPastelID, vData))
        return false;
    if (vData.size() != PASTELID_PUBKEY_SIZE + sizeof(PASTELID_PREFIX) ||
        !equal(cbegin(PASTELID_PREFIX), cend(PASTELID_PREFIX), vData.cbegin()))
        return false;
    vData.erase(vData.cbegin(), vData.cbegin() + sizeof(PASTELID_PREFIX));
    return true;
}

string CPastelID::EncodeLegRoastPubKey(const string& sPubKey)
{
    v_uint8 vData;
    vData.reserve(sPubKey.size() + sizeof(LEGROAST_PREFIX));
    vData.assign(cbegin(LEGROAST_PREFIX), cend(LEGROAST_PREFIX));
    append_string_to_vector(sPubKey, vData);
    string sRet = EncodeBase58Check(vData);
    memory_cleanse(vData.data(), vData.size());
    return sRet;
}

bool CPastelID::DecodeLegRoastPubKey(const string& sLRKey, v_uint8& vData)
{
    if (!DecodeBase58Check(sLRKey, vData))
        return false;
    if (vData.size() != LEGROAST_PUBKEY_SIZE + sizeof(LEGROAST_PREFIX) ||
        !equal(cbegin(LEGROAST_PREFIX), cend(LEGROAST_PREFIX), vData.cbegin()))
        return false;
    vData.erase(vData.cbegin(), vData.cbegin() + sizeof(LEGROAST_PREFIX));
    return true;
}

bool CPastelID::CheckPastelKeysDirectory(fs::path &pathPastelKeys, const bool bCreateDirs)
{
    pathPastelKeys = fs::path(GetArg("-pastelkeysdir", "pastelkeys"));

    // use net-specific data dir
    pathPastelKeys = GetDataDir(true) / pathPastelKeys;

    if (bCreateDirs && (!fs::exists(pathPastelKeys) || !fs::is_directory(pathPastelKeys)))
    {
        try
        {
            if (fs::create_directory(pathPastelKeys))
                LogFnPrintf("Pastel keys directory created: [%s]", pathPastelKeys.string());
        } catch (const fs::filesystem_error & e)
        {
            return error("Failed to create pastel keys directory [%s]. %s",
                pathPastelKeys.string(), e.what());
        }
   }
    return fs::exists(pathPastelKeys);
}

/**
 * Get full path of the secure container (returns filesystem object).
 * 
 * \param sPastelID - Pastel ID (used as a file name)
 * \param bCreateDirs - if true - create directories
 * \return secure container absolute full path object
 */
fs::path CPastelID::GetSecureContFilePathEx(const string& sPastelID, const bool bCreateDirs)
{
    fs::path pathPastelKeys;
    CheckPastelKeysDirectory(pathPastelKeys, bCreateDirs);
    return pathPastelKeys / sPastelID;
}

/**
 * Get full path of the secure container (returns string).
 * 
 * \param sPastelID - Pastel ID (used as a file name)
 * \param bCreateDirs - if true - create directories
 * \return secure container absolute full path
 */
string CPastelID::GetSecureContFilePath(const string& sPastelID, const bool bCreateDirs)
{
    return GetSecureContFilePathEx(sPastelID, bCreateDirs).string();
}
```

src/pastelid/ed.h
```
#pragma once

#include <sstream>
#include <iostream>
#include <fstream>
#include <memory>
#include <cmath>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <utils/vector_types.h>
#include <pastelid/common.h>
#include <pastelid/secure_container.h>

//EdDSA uses small public keys ED25519 - 32 bytes; ED448 - 57 bytes
// and signatures ED25519 - 64 bytes; Ed448 - 114 bytes

//DER prefixes
// for private keys: 3047020100300506032b6571043b0439
// for public keys:  3043300506032b6571033a00

namespace ed_crypto {

    template<int type>
    class key
    {

        struct KeyCtxDeleterFunctor {
            void operator()(EVP_PKEY_CTX *ctx) {
                EVP_PKEY_CTX_free(ctx);
            }
        };
        struct KeyDeleterFunctor {
            void operator()(EVP_PKEY *pkey) {
                EVP_PKEY_free(pkey);
            }
        };
        struct FileCloserFunctor {
            void operator()(FILE *fp) {
                std::fclose(fp);
            }
        };

        using unique_key_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, KeyCtxDeleterFunctor>;
        using unique_file_ptr = std::unique_ptr<FILE, FileCloserFunctor>;

    public:
        using unique_key_ptr = std::unique_ptr<EVP_PKEY, KeyDeleterFunctor>;

        key(unique_key_ptr key) : 
            key_(std::move(key))
        {}

        EVP_PKEY* get() const noexcept { return key_.get(); }

        static key generate_key()
        {
            unique_key_ctx_ptr ctx(EVP_PKEY_CTX_new_id(type, nullptr));
            if (!ctx)
                throw crypto_exception("Key context is NULL!", std::string(), "EVP_PKEY_CTX_new_id");

            EVP_PKEY_CTX *pctx = ctx.get();

            if (OK != EVP_PKEY_keygen_init(pctx))
                throw crypto_exception("", std::string(), "EVP_PKEY_keygen_init");

            EVP_PKEY *pkey = nullptr;
            if (OK != EVP_PKEY_keygen(pctx, &pkey))
                throw crypto_exception("", std::string(), "EVP_PKEY_keygen");

            if (!pkey)
                throw crypto_exception("Key is NULL!", std::string(), "EVP_PKEY_keygen");

            unique_key_ptr uniqueKeyPtr(pkey);
            key key(std::move(uniqueKeyPtr));
            return key;
        }

        static key create_from_private(const std::string& privateKey, const std::string& passPhrase)
        {
            auto bio = stream::unique_bio_ptr(BIO_new_mem_buf(privateKey.c_str(), static_cast<int>(privateKey.size())));

            auto pPassPhrase = passPhrase.empty()? nullptr: const_cast<char*>(passPhrase.c_str());
            unique_key_ptr uniqueKeyPtr(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, pPassPhrase));
            if (!uniqueKeyPtr)
                throw crypto_exception("Cannot read key from string", std::string(), "PEM_read_bio_PrivateKey");

            key key(std::move(uniqueKeyPtr));
            return key;
        }

        static key create_from_public(const std::string& publicKey)
        {
            auto bio = stream::unique_bio_ptr(BIO_new_mem_buf(publicKey.c_str(), static_cast<int>(publicKey.size())));

            unique_key_ptr uniqueKeyPtr(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
            if (!uniqueKeyPtr)
                throw crypto_exception("Cannot read public key from string", std::string(), "PEM_read_bio_PUBKEY");

            key key(std::move(uniqueKeyPtr));
            return key;
        }

        static key create_from_raw_private(const unsigned char* rawprivkey, size_t keylen)
        {
            unique_key_ptr uniqueKeyPtr(EVP_PKEY_new_raw_private_key(type, nullptr, rawprivkey, keylen));
            if (!uniqueKeyPtr)
                throw crypto_exception("Cannot read private key from string", std::string(), "EVP_PKEY_new_raw_private_key");

            key key(std::move(uniqueKeyPtr));
            return key;
        }

        static key create_from_raw_public(const unsigned char *rawkey, size_t keylen)
        {
            unique_key_ptr uniqueKeyPtr(EVP_PKEY_new_raw_public_key(type, nullptr, rawkey, keylen));
            if (!uniqueKeyPtr)
                throw crypto_exception("Cannot read public key from string", std::string(), "EVP_PKEY_new_raw_public_key");

            key key(std::move(uniqueKeyPtr));
            return key;
        }

        static key create_from_raw_public_hex(const std::string& rawPublicKey)
        {
            v_uint8 vec = Hex_Decode(rawPublicKey);
            return create_from_raw_public(vec.data(), vec.size());
        }

        static key create_from_raw_public_base64(const std::string& rawPublicKey)
        {
            v_uint8 vec = Base64_Decode(rawPublicKey);
            return create_from_raw_public(vec.data(), vec.size());
        }

        static key read_private_key_from_PKCS8_file(const std::string& fileName, const std::string& passPhrase)
        {
            std::ifstream file(fileName);
            if (!file)
                throw crypto_exception("Cannot open file to read key from", fileName, "fopen");

            std::stringstream buffer;
            buffer << file.rdbuf();
            return create_from_private(buffer.str(), passPhrase);
        }

        std::string public_key() const
        {
            return stream::bioToString(BIO_s_mem(), [this](BIO* bio)
            {
                return PEM_write_bio_PUBKEY(bio, key_.get());
            });
        }

        std::string private_key() const
        {
            return stream::bioToString(BIO_s_mem(), [this](BIO* bio)
            {
                return PEM_write_bio_PrivateKey(bio, key_.get(), nullptr, nullptr, 0, nullptr, nullptr);
            });
        }

        buffer public_key_raw() const
        {
            std::size_t raw_key_len = 0;
            // Get length of the raw key
            if (OK != EVP_PKEY_get_raw_public_key(key_.get(), nullptr, &raw_key_len)) {
                throw crypto_exception("Cannot get length of raw public key", std::string(), "EVP_PKEY_get_raw_public_key");
            }
            if (0 == raw_key_len)
                throw crypto_exception("Returned length is 0!", std::string(), "EVP_PKEY_get_raw_public_key");

            // Allocate memory for the key based on size in raw_key_len
            auto prawkey = static_cast<unsigned char *>(OPENSSL_malloc(raw_key_len));
            if (!prawkey)
                throw crypto_exception("Returned buffer is NULL!", std::string(), "public_key_raw/OPENSSL_malloc");

            // Obtain the raw key
            if (OK != EVP_PKEY_get_raw_public_key(key_.get(), prawkey, &raw_key_len))
                throw crypto_exception("Cannot get raw public key", std::string(), "EVP_PKEY_get_raw_public_key");

            buffer rawkey(prawkey, raw_key_len);
            return rawkey;
        }

        std::string public_key_raw_hex() const
        {
            return public_key_raw().Hex();
        }

        std::string public_key_raw_base64() const
        {
            return public_key_raw().Base64();
        }

        buffer private_key_raw() const
        {
            std::size_t raw_key_len = 0;
            // Get length of the raw key
            if (OK != EVP_PKEY_get_raw_private_key(key_.get(), nullptr, &raw_key_len)) {
                throw (crypto_exception("Cannot get length of raw public key", std::string(), "EVP_PKEY_get_raw_private_key"));
            }
            if (0 == raw_key_len) {
                throw (crypto_exception("Returned length is 0!", std::string(), "EVP_PKEY_get_raw_private_key"));
            }

            // Allocate memory for the key based on size in raw_key_len
            auto prawkey = (unsigned char *) OPENSSL_malloc(raw_key_len);
            if (nullptr == prawkey)
                throw (crypto_exception("Returned buffer is NULL!", std::string(), "private_key_raw/OPENSSL_malloc"));

            // Obtain the raw key
            if (OK != EVP_PKEY_get_raw_private_key(key_.get(), prawkey, &raw_key_len))
                throw (crypto_exception("Cannot get raw public key", std::string(), "EVP_PKEY_get_raw_private_key"));

            buffer rawkey(prawkey, raw_key_len);
            return rawkey;
        }

        std::string private_key_raw_hex() const
        {
            return private_key_raw().Hex();
        }

        std::string private_key_raw_base64() const
        {
            return private_key_raw().Base64();
        }

    private:

        buffer generate_shared_secret(key &remoteKey) {

            unique_key_ctx_ptr ctxDeriv(EVP_PKEY_CTX_new(key_.get(), nullptr));
            if (!ctxDeriv) {
                throw (crypto_exception("Derived Key context is NULL!", std::string(), "EVP_PKEY_CTX_new"));
            }

            EVP_PKEY_CTX *pctxDeriv = ctxDeriv.get();

            if (OK != EVP_PKEY_derive_init(pctxDeriv)) {
                throw (crypto_exception("", std::string(), "EVP_PKEY_derive_init"));
            }

            if (OK != EVP_PKEY_derive_set_peer(pctxDeriv, remoteKey.key_.get())) {
                throw (crypto_exception("", std::string(), "EVP_PKEY_derive_set_peer"));
            }

            std::size_t secret_len = 0;
            // Determine buffer length for shared secret
            if (OK != EVP_PKEY_derive(pctxDeriv, nullptr, &secret_len)) {
                throw (crypto_exception("", std::string(), "EVP_PKEY_derive"));
            }
            if (0 == secret_len) {
                throw (crypto_exception("Returned length is 0!", std::string(), "EVP_PKEY_derive"));
            }

            auto psecret = (unsigned char *) OPENSSL_malloc(secret_len);
            if (nullptr == psecret)
                throw (crypto_exception("Returned buffer is NULL!", std::string(), "OPENSSL_malloc"));

            // Derive the shared secret
            if (OK != EVP_PKEY_derive(pctxDeriv, psecret, &secret_len))
                throw (crypto_exception("", std::string(), "EVP_PKEY_derive"));

            buffer secret(psecret, secret_len);
            return secret;
        }

    private:
        unique_key_ptr key_;
    };

    //ed DSA
    class crypto_sign {

        struct MdCtxDeleterFunctor {
            void operator()(EVP_MD_CTX *ctx) {
                EVP_MD_CTX_destroy(ctx);
            }
        };

        using unique_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleterFunctor>;

    public:

        crypto_sign() = default;

        template<int type>
        static buffer sign(const unsigned char* message, std::size_t length, const key<type>& secret_key)
        {
            unique_md_ctx_ptr ctx(EVP_MD_CTX_create());
            if (!ctx) throw (crypto_exception("MD context is NULL!", std::string(), "EVP_MD_CTX_create"));

            EVP_MD_CTX *mdctx = ctx.get();
            EVP_PKEY *pkey = secret_key.get();

            // Initialise the DigestSign operation - EdDSA has builtin digest function
            if (OK != EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey)) {
                throw (crypto_exception("", std::string(), "EVP_DigestSignInit"));
            }

            std::size_t signature_len = 0;
            // Get length of the signature
            if (OK != EVP_DigestSign(mdctx, nullptr, &signature_len, message, length)) {
                throw (crypto_exception("", std::string(), "EVP_DigestSign"));
            }
            if (0 == signature_len) {
                throw (crypto_exception("Returned length is 0!", std::string(), "EVP_DigestSign"));
            }

            // Allocate memory for the signature based on size in slen
            auto psignature = (unsigned char *) OPENSSL_malloc(signature_len);
            if (nullptr == psignature)
                throw (crypto_exception("Returned buffer is NULL!", std::string(), "OPENSSL_malloc"));

            // Obtain the signature
            if (OK != EVP_DigestSign(mdctx, psignature, &signature_len, message, length))
                throw (crypto_exception("", std::string(), "EVP_DigestSign"));

            buffer signature(psignature, signature_len);
            return signature;
        }

        template<int type>
        static buffer sign_base64(const std::string& messageBase64, const key<type>& secret_key)
        {
            v_uint8 vec = Base64_Decode(messageBase64);
            return sign(vec.data(), vec.size(), secret_key);
        }

        template<int type>
        static buffer sign_hex(const std::string& messageHex, const key<type>& secret_key)
        {
            v_uint8 vec = Hex_Decode(messageHex);
            return sign(vec.data(), vec.size(), secret_key);
        }

        template<int type>
        static buffer sign(const std::string& message, const key<type>& secret_key)
        {
            return sign(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(), secret_key);
        }
    
        template<int type>
        static bool verify(const unsigned char* message, std::size_t msglen, const unsigned char* signature, std::size_t siglen, const key<type>& public_key)
        {
            unique_md_ctx_ptr ctx(EVP_MD_CTX_create());
            if (!ctx)
                throw crypto_exception("MD context is NULL!", std::string(), "EVP_MD_CTX_create");
    
            EVP_MD_CTX *mdctx = ctx.get();
            EVP_PKEY *pkey = public_key.get();
    
            // Initialise the DigestVerify operation - EdDSA has builtin digest function
            if (OK != EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey))
                throw crypto_exception("", std::string(), "EVP_DigestVerifyInit");
    
            // Verify the signature
            return (OK == EVP_DigestVerify(mdctx, signature, siglen, message, msglen));
        }
        
        template<int type>
        static bool verify(const std::string& message, const unsigned char* signature, std::size_t siglen, const key<type>& public_key)
        {
            return verify(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(), signature, siglen, public_key);
        }
    
        template<int type>
        static bool verify(const std::string& message, const std::string& signature, const key<type>& public_key)
        {
            return verify(reinterpret_cast <const unsigned char*>(message.c_str()), message.length(),
                          reinterpret_cast <const unsigned char*>(signature.c_str()), signature.length(), public_key);
        }

        template<int type>
        static bool verify_base64(const std::string& message, const std::string& signatureBase64, const key<type>& public_key)
        {
            v_uint8 vec = Base64_Decode(signatureBase64);
            return verify(message, vec.data(), vec.size(), public_key);
        }

        template<int type>
        static bool verify_hex(const std::string& message, const std::string& signatureHex, const key<type>& public_key)
        {
            v_uint8 vec = Hex_Decode(signatureHex);
            return verify(message, vec.data(), vec.size(), public_key);
        }
    };

    //ed DH
    class crypto_box {
        static std::string encrypt()
        {
            return std::string();
        }

        static std::string decrypt()
        {
            return std::string();
        }
    };

    using key_dsa448 = key<EVP_PKEY_ED448>;
    using key_dh448 = key<EVP_PKEY_X448>;
    using key_dsa25519 = key<EVP_PKEY_ED25519>;
    using key_hd25519 = key<EVP_PKEY_X25519>;
}
```

---

Now, here is what I have so far in my rust code:


Cargo.toml
```

[package]
name = "pastelid_signer"
version = "0.1.0"
edition = "2021"

[dependencies]
ed448-rust = "0.1.1"
sodiumoxide = "0.2.7"
config = "0.14.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rmp-serde = "1.0"
hex = "0.4.3"

[dependencies.pyo3]
version = "0.21.2"
features = ["extension-module"]


```

lib.rs
```
use core::convert::TryFrom;
use ed448_rust::{PrivateKey, PublicKey};
use pyo3::prelude::*;
use sodiumoxide::crypto::pwhash::{self, Salt, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{self, Nonce, Key};
use std::fs;
use serde::{Deserialize, Serialize};
use rmp_serde::Deserializer;
use std::io::Cursor;

#[pyclass]
struct PastelSigner {
    private_key: PrivateKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureContainer {
    version: u16,
    timestamp: i64,
    encryption: String,
    secure_items: Vec<SecureItem>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureItem {
    #[serde(rename = "type")]
    item_type: String,
    nonce: Vec<u8>,
    data: Vec<u8>,
}

#[pymethods]
impl PastelSigner {
    #[new]
    fn new() -> Self {
        sodiumoxide::init().expect("Failed to initialize sodiumoxide");

        // Read the configuration file
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config"))
            .build()
            .expect("Failed to read config file");

        let file_path: String = settings.get_string("pastelid.file_path").expect("Missing file_path key");
        let passphrase: String = settings.get_string("pastelid.passphrase").expect("Missing passphrase key");

        println!("Secure container file path: {}", file_path);

        // Read the SecureContainer file
        let encrypted_data = fs::read(&file_path).expect("Failed to read file");

        // Verify file header
        let header = b"PastelSecureContainer";
        if &encrypted_data[..header.len()] != header {
            panic!("Invalid file header");
        }
        println!("Valid file header");

        // Skip the header and extract the rest of the data
        let encrypted_data = &encrypted_data[header.len()..];

        // Print the raw data length and some of its content for debugging
        println!("Raw data length: {}", encrypted_data.len());
        println!("Raw data snippet: {:?}", &encrypted_data[..std::cmp::min(100, encrypted_data.len())]);

        // Deserialize the encrypted data
        let mut de = Deserializer::new(Cursor::new(encrypted_data));
        let secure_container: SecureContainer = match Deserialize::deserialize(&mut de) {
            Ok(container) => container,
            Err(e) => {
                println!("Failed to deserialize secure container: {:?}", e);
                panic!("Deserialization error");
            }
        };

        println!("Deserialized secure container: {:?}", secure_container);

        // Extract the private key from the secure container
        let secure_item = secure_container.secure_items
            .iter()
            .find(|item| item.item_type == "pkey_ed448")
            .expect("Private key not found in the secure container");

        let private_key_data = &secure_item.data;
        let nonce_slice = &secure_item.nonce;

        if nonce_slice.len() != xchacha20poly1305_ietf::NONCEBYTES {
            panic!("Invalid nonce length: expected {}, got {}", xchacha20poly1305_ietf::NONCEBYTES, nonce_slice.len());
        }
        println!("Nonce slice: {:?}", nonce_slice);

        let nonce = Nonce::from_slice(&nonce_slice).expect("Failed to create nonce");

        // Derive a key from the passphrase using libsodium's crypto_pwhash
        let salt = Salt::from_slice(&nonce_slice).expect("Failed to create salt from nonce slice");

        let mut key = [0u8; xchacha20poly1305_ietf::KEYBYTES];
        pwhash::derive_key(
            &mut key,
            passphrase.as_bytes(),
            &salt,
            OPSLIMIT_INTERACTIVE,
            MEMLIMIT_INTERACTIVE
        ).expect("Failed to derive key");

        println!("Derived key: {:?}", key);

        // Decrypt the private key data using the passphrase-derived key
        let decrypted_private_key_data = match xchacha20poly1305_ietf::open(
            &private_key_data,
            None,
            &nonce,
            &Key::from_slice(&key).unwrap()
        ) {
            Ok(data) => data,
            Err(_) => {
                println!("Failed to decrypt the data. Key: {:?}, Nonce: {:?}", key, nonce_slice);
                panic!("Failed to decrypt");
            }
        };

        let private_key = PrivateKey::try_from(&decrypted_private_key_data[..]).expect("Failed to create PrivateKey");

        PastelSigner { private_key }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.private_key.sign(message, None).expect("Failed to sign");
        signature.to_vec()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let public_key = PublicKey::from(&self.private_key);
        public_key.verify(message, signature, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_sign_and_verify() {
        let signer = PastelSigner::new();

        let message1 = "my_message_1__hello_friends".as_bytes();
        let signature1 = signer.sign(message1);
        assert_eq!(
            hex::encode(&signature1),
            "XUrsiNwSHkgacI1iRcUkC+G82dIkEgVvhzUD1awhICkvqBGUgKho7dAWpwKUhNctRJpayS4F89qAS58urukEYs2l9hPYocK/o6gGlZ3kihkzTf7lYC+dC7VAiShiJmJM85t6GjZ3saA6jxIk/BXgqjgA"
        );
        assert!(signer.verify(message1, &signature1));

        let message2 = "my_message_2__hello_friends".as_bytes();
        let signature2 = signer.sign(message2);
        assert_eq!(
            hex::encode(&signature2),
            "CEnpEHHxenDkY6/4oOLyhqjt5Y646OKN9JJXOhOz8qWxCC6D/qrDlEeDYQlYhvRgCQKQUbSGkdQAhEXjGPaNv6oWbTO7CLF9RLHeoLGhx5SFHF0L9WVK021G48MolJJqdSdSjUaiVK8bLJlpXzbgTikA"
        );
        assert!(signer.verify(message2, &signature2));

        let invalid_signature = hex::decode("TESTCEnpEHHxenDkY6/4oOLyhqjt5Y646OKN9JJXOhOz8qWxCC6D").unwrap();
        assert!(!signer.verify(message1, &invalid_signature));
    }
}


```

Those test cases were made using pasteld's RPC methods, so I know they are right.

It's not working though-- see these errors:

```
❯ RUST_BACKTRACE=1 cargo test
   Compiling pastelid_signer v0.1.0 (/home/ubuntu/pastelid_signer)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.45s
     Running unittests src/lib.rs (target/debug/deps/pastelid_signer-ac67b9c6555f33f5)

running 1 test
test tests::test_sign_and_verify ... FAILED

failures:

---- tests::test_sign_and_verify stdout ----
Secure container file path: test_secure_container_file/jXXfLwrL7s7BQpm1uapzhKirt2HaRAse8Wru8pRLcGLonmZ996xNzAPJBjR6wfVXVzVFWn3NwA79gyAB5BptJ7
Valid file header
Raw data length: 5985
Raw data snippet: [0, 0, 0, 0, 0, 0, 22, 24, 251, 13, 227, 74, 116, 50, 68, 232, 217, 241, 171, 186, 187, 126, 241, 43, 198, 224, 57, 252, 74, 56, 54, 133, 0, 149, 125, 146, 207, 254, 138, 214, 130, 167, 118, 101, 114, 115, 105, 111, 110, 1, 172, 112, 117, 98, 108, 105, 99, 95, 105, 116, 101, 109, 115, 145, 130, 164, 116, 121, 112, 101, 175, 112, 117, 98, 107, 101, 121, 95, 108, 101, 103, 114, 111, 97, 115, 116, 164, 100, 97, 116, 97, 197, 21, 226, 69, 120, 119, 89, 101, 90]
Failed to deserialize secure container: Syntax("invalid type: integer `0`, expected struct SecureContainer")
thread 'tests::test_sign_and_verify' panicked at src/lib.rs:72:17:
Deserialization error
stack backtrace:
   0: rust_begin_unwind
             at /rustc/b5b13568fb5da4ac988bde370008d6134d3dfe6c/library/std/src/panicking.rs:652:5
   1: core::panicking::panic_fmt
             at /rustc/b5b13568fb5da4ac988bde370008d6134d3dfe6c/library/core/src/panicking.rs:72:14
   2: pastelid_signer::PastelSigner::new
             at ./src/lib.rs:72:17
   3: pastelid_signer::tests::test_sign_and_verify
             at ./src/lib.rs:145:22
   4: pastelid_signer::tests::test_sign_and_verify::{{closure}}
             at ./src/lib.rs:144:30
   5: core::ops::function::FnOnce::call_once
             at /rustc/b5b13568fb5da4ac988bde370008d6134d3dfe6c/library/core/src/ops/function.rs:250:5
   6: core::ops::function::FnOnce::call_once
             at /rustc/b5b13568fb5da4ac988bde370008d6134d3dfe6c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.


failures:
    tests::test_sign_and_verify

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s

error: test failed, to rerun pass `--lib`
```