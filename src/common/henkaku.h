/**
 * @brief      Internal functions and defines
 */
#ifndef __HENKAKU_HEADER__
#define __HENKAKU_HEADER__

#include "config.h"

#include <stdbool.h>
#include <stdint.h>

int henkaku_reload_config(void);
int taiReloadConfig(void);

#define UNUSED_PARAM(x) ((void)(x))

/** Logging function */
#ifdef ENABLE_LOGGING
#ifdef __VITA_KERNEL__
#define LOG(fmt, ...) ksceKernelPrintf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) sceClibPrintf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif
#else
#define LOG(fmt, ...)
#endif

/** Config */
typedef struct
{
	uint32_t magic;
	uint32_t version;
	uint32_t use_psn_spoofing;
	uint32_t allow_unsafe_hb;
	uint32_t use_spoofed_version;
	uint32_t spoofed_version;
} __attribute__((packed)) henkaku_config_t;

#define HENKAKU_CONFIG_MAGIC (0x4C434C4D) /* MLCL */
#define CONFIG_PATH          "ur0:tai/henkaku_config.bin"
#define OLD_CONFIG_PATH      "ux0:temp/app_work/MLCL00001/rec/config.bin"
#define SPOOF_VERSION        (0x03740000)

#define henkaku_default_config(config)                       \
do {                                                         \
	(config).magic               = HENKAKU_CONFIG_MAGIC; \
	(config).version             = HENKAKU_RELEASE;      \
	(config).use_psn_spoofing    = true;                 \
	(config).allow_unsafe_hb     = false;                \
	(config).use_spoofed_version = true;                 \
	(config).spoofed_version     = SPOOF_VERSION;        \
} while (false)

#endif // __HENKAKU_HEADER__
