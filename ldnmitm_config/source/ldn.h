#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Service s;
} UserLocalCommunicationService;
typedef struct {
    Service s;
} LdnMitmConfigService;
#define SsidLengthMax 32
#define AdvertiseDataSizeMax 384
#define UserNameBytesMax 32
#define NodeCountMax 8
#define PassphraseLengthMax 64

typedef struct {
    uint8_t bssid[6];
    uint8_t ssidLength;
    char ssid[SsidLengthMax + 1];
    int16_t channel;
    int8_t linkLevel;
    uint8_t networkType;
    uint32_t _unk;
} CommonNetworkInfo;

typedef struct {
    uint32_t ipv4Address;
    uint8_t macAddress[6];
    int8_t nodeId;
    int8_t isConnected;
    char userName[UserNameBytesMax+1];
    uint8_t _unk1;
    int16_t localCommunicationVersion;
    uint8_t _unk2[16];
} NodeInfo;

/// Ipv4Address. This is essentially the same as struct in_addr - hence this can be used with standard sockets (byteswap required).
typedef struct {
    uint32_t addr;                          ///< Address
} LdnIpv4Address;

/// MacAddress
typedef struct {
    uint8_t addr[6];                        ///< Address
} LdnMacAddress;

/// Ssid
typedef struct {
    uint8_t len;                            ///< Length excluding NUL-terminator, must be 0x1-0x20.
    char str[0x21];                    ///< SSID string including NUL-terminator, str[len_field] must be 0. The chars in this string must be be in the range of 0x20-0x7F, for when the Ssid is converted to a string (otherwise the byte written to the string will be 0).
} LdnSsid;

/// NodeInfo
typedef struct {
    LdnIpv4Address ip_addr;            ///< \ref LdnIpv4Address
    LdnMacAddress mac_addr;            ///< \ref LdnMacAddress
    int8_t id;                             ///< ID / index
    uint8_t is_connected;                   ///< IsConnected flag
    char nickname[0x20];               ///< LdnUserConfig::nickname
    uint8_t reserved_x2C[0x2];              ///< Reserved
    int16_t local_communication_version;   ///< LocalCommunicationVersion
    uint8_t reserved_x30[0x10];             ///< Reserved
} LdnNodeInfo;

/// NetworkInfo
typedef struct {
    uint64_t local_communication_id;        ///< LocalCommunicationId
    uint8_t reserved_x8[0x2];               ///< Reserved
    uint16_t userdata_filter;               ///< Arbitrary user data which can be used for filtering with \ref LdnScanFilter.
    uint8_t reserved_xC[0x4];               ///< Reserved
    uint8_t network_id[0x10];               ///< LdnSecurityParameter::network_id. NetworkId which is used to generate/overwrite the ssid. With \ref ldnScan / \ref ldnScanPrivate, this is only done after filtering when unk_x4B is value 0x2.
    LdnMacAddress mac_addr;            ///< \ref LdnMacAddress
    LdnSsid ssid;                      ///< \ref LdnSsid
    int16_t network_channel;               ///< NetworkChannel
    int8_t link_level;                     ///< LinkLevel
    uint8_t unk_x4B;                        ///< Unknown. Set to hard-coded value 0x2 with output structs, except with \ref ldnScan / \ref ldnScanPrivate which can also set value 0x1 in certain cases.
    uint8_t pad_x4C[0x4];                   ///< Padding
    uint8_t sec_param_data[0x10];           ///< LdnSecurityParameter::data
    uint16_t sec_type;                      ///< LdnSecurityConfig::type
    uint8_t accept_policy;                  ///< \ref LdnAcceptPolicy
    uint8_t unk_x63;                        ///< Only set with \ref ldnScan / \ref ldnScanPrivate, when unk_x4B is value 0x2.
    uint8_t pad_x64[0x2];                   ///< Padding
    int8_t participant_max;                ///< Maximum participants, for nodes.
    uint8_t participant_num;                ///< ParticipantNum, number of set entries in nodes. If unk_x4B is not 0x2, ParticipantNum should be handled as if it's 0.
    LdnNodeInfo nodes[8];              ///< Array of \ref LdnNodeInfo, starting with the AccessPoint node.
    uint8_t reserved_x268[0x2];             ///< Reserved
    uint16_t advertise_data_size;           ///< AdvertiseData size (\ref ldnSetAdvertiseData)
    uint8_t advertise_data[0x180];          ///< AdvertiseData (\ref ldnSetAdvertiseData)
    uint8_t reserved_x3EC[0x8C];            ///< Reserved
    uint64_t auth_id;                       ///< Random AuthenticationId.
} LdnNetworkInfo;

typedef struct {
    uint64_t localCommunicationId;
    uint8_t _unk1[2];
    uint16_t sceneId;
    uint8_t _unk2[4];
} IntentId;

typedef struct {
    uint64_t high;
    uint64_t low;
} SessionId;

typedef struct {
    IntentId intentId;      // 16bytes
    SessionId sessionId;    // 16bytes
} NetworkId;                // 32bytes

typedef struct {
    NetworkId networkId;
    CommonNetworkInfo common;
    LdnNetworkInfo ldn;
} NetworkInfo;

typedef struct {
    uint16_t securityMode;
    uint16_t passphraseSize;
    uint8_t passphrase[PassphraseLengthMax];
} SecurityConfig;

typedef struct {
    char userName[UserNameBytesMax + 1];
    uint8_t _unk[15];
} UserConfig;

typedef struct {
    IntentId intentId;      // 16byte
    uint16_t channel;
    uint8_t nodeCountMax;
    uint8_t _unk1;
    uint16_t localCommunicationVersion;
    uint8_t _unk2[10];
} NetworkConfig;            // 32bytes

typedef struct {
    SecurityConfig securityConfig;
    UserConfig userConfig;
    uint8_t _unk[4];
    NetworkConfig networkConfig;
} CreateNetworkConfig;

typedef struct {
    SecurityConfig securityConfig;
    UserConfig userConfig;
    uint32_t version;
    uint32_t option;
} ConnectNetworkData;

typedef struct {
    uint8_t stateChange;
    uint8_t _unk[7];
} NodeLatestUpdate;

typedef struct {
    uint8_t unkRandom[16];
    SessionId sessionId;
} SecurityParameter;

Result ldnGetNetworkInfo(LdnNetworkInfo *out);
Result ldnScan(s32 channel, const LdnScanFilter *filter, LdnNetworkInfo *network_info, s32 count, s32 *total_out);
Result ldnCreateUserLocalCommunicationService(Service* s, UserLocalCommunicationService* out);
Result ldnInitialize(LdnServiceType service_type);
Result ldnOpenStation(void);
Result ldnGetState(LdnState *out);
Result ldnMitmSaveLogToFile(LdnMitmConfigService *s);
Result ldnMitmGetVersion(LdnMitmConfigService *s, char *version);
Result ldnMitmGetLogging(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetLogging(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetEnabled(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetEnabled(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetConfig(LdnMitmConfigService *out);
Result ldnMitmGetConfigFromService(Service* s, LdnMitmConfigService *out);
void NetworkInfo2NetworkConfig(NetworkInfo* info, NetworkConfig* out);
void NetworkInfo2SecurityParameter(NetworkInfo* info, SecurityParameter* out);

#ifdef __cplusplus
}
#endif
