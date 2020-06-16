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

/// NetworkInfo
typedef struct {
    u64 local_communication_id;        ///< LocalCommunicationId
    u8 reserved_x8[0x2];               ///< Reserved
    u16 userdata_filter;               ///< Arbitrary user data which can be used for filtering with \ref LdnScanFilter.
    u8 reserved_xC[0x4];               ///< Reserved
    u8 network_id[0x10];               ///< LdnSecurityParameter::network_id. NetworkId which is used to generate/overwrite the ssid. With \ref ldnScan / \ref ldnScanPrivate, this is only done after filtering when unk_x4B is value 0x2.
    LdnMacAddress mac_addr;            ///< \ref LdnMacAddress
    LdnSsid ssid;                      ///< \ref LdnSsid
    s16 network_channel;               ///< NetworkChannel
    s8 link_level;                     ///< LinkLevel
    u8 unk_x4B;                        ///< Unknown. Set to hard-coded value 0x2 with output structs, except with \ref ldnScan / \ref ldnScanPrivate which can also set value 0x1 in certain cases.
    u8 pad_x4C[0x4];                   ///< Padding
    u8 sec_param_data[0x10];           ///< LdnSecurityParameter::data
    u16 sec_type;                      ///< LdnSecurityConfig::type
    u8 accept_policy;                  ///< \ref LdnAcceptPolicy
    u8 unk_x63;                        ///< Only set with \ref ldnScan / \ref ldnScanPrivate, when unk_x4B is value 0x2.
    u8 pad_x64[0x2];                   ///< Padding
    s8 participant_max;                ///< Maximum participants, for nodes.
    u8 participant_num;                ///< ParticipantNum, number of set entries in nodes. If unk_x4B is not 0x2, ParticipantNum should be handled as if it's 0.
    LdnNodeInfo nodes[8];              ///< Array of \ref LdnNodeInfo, starting with the AccessPoint node.
    u8 reserved_x268[0x2];             ///< Reserved
    u16 advertise_data_size;           ///< AdvertiseData size (\ref ldnSetAdvertiseData)
    u8 advertise_data[0x180];          ///< AdvertiseData (\ref ldnSetAdvertiseData)
    u8 reserved_x3EC[0x8C];            ///< Reserved
    u64 auth_id;                       ///< Random AuthenticationId.
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
