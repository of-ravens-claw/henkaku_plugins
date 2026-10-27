#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/registrymgr.h>
#include <psp2/system_param.h>
#include <psp2/power.h>
#include <psp2/vshbridge.h>
#include <taihen.h>

#include "henkaku.h"
#include "language.h"
#include "config.h"

// These are missing from VitaSDK.
#define SCE_ERROR_ERRNO_ENOENT ((int)0x80010002)
#define SCE_ERROR_ERRNO_EEXIST ((int)0x80010011)
#define SCE_UID_INVALID_UID    ((SceUID)-1)

extern unsigned char _binary_system_settings_330_xml_start;
extern unsigned char _binary_system_settings_330_xml_size;
extern unsigned char _binary_system_settings_350_xml_start;
extern unsigned char _binary_system_settings_350_xml_size;

extern unsigned char _binary_henkaku_settings_xml_start;
extern unsigned char _binary_henkaku_settings_xml_size;

static void* _binary_system_settings_xml_start = NULL;
static int   _binary_system_settings_xml_size  = 0;

static henkaku_config_t config;

static SceUID g_hooks[16];

// `versionString` must be at least 28 bytes long.
static int getHenkakuVersionString(char* versionString)
{
	int len = 0;

	SceKernelSystemSwVersion real_info;
	sceClibMemset(&real_info, 0, sizeof(SceKernelSystemSwVersion));
	real_info.size = sizeof(SceKernelSystemSwVersion);
	_vshSblGetSystemSwVersion(&real_info);
	
	sceClibMemset(versionString, 0, 28);
	if (BETA_RELEASE)
		len = sceClibSnprintf(versionString, 27, "%s \xE5\xA4\x89\xE9\x9D\xA9-%d\xCE\xB2%d \xE3\x81\xAE", real_info.versionString, HENKAKU_RELEASE, BETA_RELEASE);
	else if (HENKAKU_RELEASE > 1)
		len = sceClibSnprintf(versionString, 27, "%s \xE5\xA4\x89\xE9\x9D\xA9-%d \xE3\x81\xAE", real_info.versionString, HENKAKU_RELEASE);
	else
		len = sceClibSnprintf(versionString, 27, "%s \xE5\xA4\x89\xE9\x9D\xA9 \xE3\x81\xAE", real_info.versionString);
	versionString[len] = '\0';

	return len;
}

static tai_hook_ref_t g_sceKernelGetSystemSwVersion_SceSettings_hook;
static int sceKernelGetSystemSwVersion_SceSettings_patched(SceKernelSystemSwVersion* info)
{
	int ret = TAI_CONTINUE(int, g_sceKernelGetSystemSwVersion_SceSettings_hook, info);
	getHenkakuVersionString(info->versionString);
	return ret;
}

typedef struct
{
	char*  str;
	size_t len;
} paf_string_t;

static void* (*sce_paf_operator_new)(size_t size) = NULL;

static tai_hook_ref_t g_get_version_string_hook;
static void get_version_string_patched(paf_string_t* pStr)
{
	char* str = (char*)sce_paf_operator_new(28);
	int   len = getHenkakuVersionString(str);
	pStr->str = str;
	pStr->len = len;
}

static tai_hook_ref_t g_update_check_hook;
static int update_check_patched(int a1, int a2, int* a3, int a4, int a5)
{
	TAI_CONTINUE(int, g_update_check_hook, a1, a2, a3, a4, a5);
	*a3 = 0;
	return 0;
}

static tai_hook_ref_t g_game_update_check_hook;
static int game_update_check_patched(int newver, int* needsupdate)
{
	TAI_CONTINUE(int, g_game_update_check_hook, newver, needsupdate);
	*needsupdate = 0;
	return 0;
}

static tai_hook_ref_t g_passphrase_decrypt_hook;
static void passphrase_decrypt_patched(void* dat0, void* dat1, void* dat2, char* passphrase, int* result)
{
	TAI_CONTINUE(void, g_passphrase_decrypt_hook, dat0, dat1, dat2, passphrase, result);
	if (config.use_psn_spoofing && PSN_PASSPHRASE[0] != '\0' && *result == 1)
	{
		sceClibMemcpy(passphrase, PSN_PASSPHRASE, sizeof(PSN_PASSPHRASE));
	}
}

static tai_hook_ref_t g_vshNpDrmIsLooseAccountBind_SceShell_hook;
static int vshNpDrmIsLooseAccountBind_SceShell_patched(void)
{
	TAI_CONTINUE(int, g_vshNpDrmIsLooseAccountBind_SceShell_hook);
	return 1;
}

static void save_config_user(void)
{
	SceUID fd;
	int rd;
	fd = sceIoOpen(CONFIG_PATH, SCE_O_TRUNC | SCE_O_CREAT | SCE_O_WRONLY, 6);
	if (fd >= 0)
	{
		rd = sceIoWrite(fd, &config, sizeof(config));
		sceIoClose(fd);
		if (rd != sizeof(config))
		{
			LOG("config not right size: %d", rd);
		}
	}
	else
	{
		LOG("could not write config file");
	}
}

static int load_config_user(void)
{
	SceUID fd;
	int rd;
	int migrate = 0;
	fd = sceIoOpen(CONFIG_PATH, SCE_O_RDONLY, 0);
	if (fd < 0)
	{
		fd = sceIoOpen(OLD_CONFIG_PATH, SCE_O_RDONLY, 0);
		migrate = 1;
	}

	if (fd >= 0)
	{
		rd = sceIoRead(fd, &config, sizeof(config));
		sceIoClose(fd);
		if (rd == sizeof(config))
		{
			if (config.magic == HENKAKU_CONFIG_MAGIC)
			{
				if (config.version >= 0)
				{
					if (migrate)
					{
						LOG("migrating settings to new path");
						save_config_user();
						sceIoRemove(OLD_CONFIG_PATH);
					}
					return 0;
				}
				else
				{
					LOG("config version too old");
				}
			}
			else
			{
				LOG("config incorrect magic: %x", config.magic);
			}
		}
		else
		{
			LOG("config not right size: %d", rd);
		}
	}
	else
	{
		LOG("config file not found");
	}

	// default config
	henkaku_default_config(config);
	return 0;
}

static tai_hook_ref_t g_sceRegMgrGetKeyInt_SceSystemSettingsCore_hook;
static int sceRegMgrGetKeyInt_SceSystemSettingsCore_patched(const char* category, const char* name, int* value)
{
	if (sceClibStrncmp(category, "/CONFIG/HENKAKU", 15) == 0)
	{
		if (value)
		{
			load_config_user();
			if (sceClibStrncmp(name, "enable_psn_spoofing", 19) == 0)
			{
				*value = config.use_psn_spoofing;
			}
			else if (sceClibStrncmp(name, "enable_unsafe_homebrew", 22) == 0)
			{
				*value = config.allow_unsafe_hb;
			}
			else if (sceClibStrncmp(name, "enable_version_spoofing", 23) == 0)
			{
				*value = config.use_spoofed_version;
			}
		}

		return 0;
	}

	return TAI_CONTINUE(int, g_sceRegMgrGetKeyInt_SceSystemSettingsCore_hook, category, name, value);
}

static tai_hook_ref_t g_sceRegMgrSetKeyInt_SceSystemSettingsCore_hook;
static int sceRegMgrSetKeyInt_SceSystemSettingsCore_patched(const char* category, const char* name, int value)
{
	if (sceClibStrncmp(category, "/CONFIG/HENKAKU", 15) == 0)
	{
		if (sceClibStrncmp(name, "enable_psn_spoofing", 19) == 0)
		{
			config.use_psn_spoofing = value;
		}
		else if (sceClibStrncmp(name, "enable_unsafe_homebrew", 22) == 0)
		{
			config.allow_unsafe_hb = value;
		}
		else if (sceClibStrncmp(name, "enable_version_spoofing", 23) == 0)
		{
			config.use_spoofed_version = value;
		}

		save_config_user();
		henkaku_reload_config();
		return 0;
	}

	return TAI_CONTINUE(int, g_sceRegMgrSetKeyInt_SceSystemSettingsCore_hook, category, name, value);
}

static void build_version_string(int version, char* string, int length)
{
	if (version && string && length >= 6)
	{
		char a = (version >> 24) & 0xF;
		char b = (version >> 20) & 0xF;
		char c = (version >> 16) & 0xF;
		char d = (version >> 12) & 0xF;
		sceClibMemset(string, 0, length);
		string[0] = '0' + a;
		string[1] = '.';
		string[2] = '0' + b;
		string[3] = '0' + c;
		string[4] = '\0';

		// For FWs like 1.691 and 1.692.
		// TODO: Was it not displayed as "1.69.1" on retail?
		if (d)
		{
			string[4] = '0' + d;
			string[5] = '\0';
		}
	}
}

static tai_hook_ref_t g_sceRegMgrGetKeyStr_SceSystemSettingsCore_hook;
static int sceRegMgrGetKeyStr_SceSystemSettingsCore_patched(const char* category, const char* name, char* string, int length)
{
	if (sceClibStrncmp(category, "/CONFIG/HENKAKU", 15) == 0)
	{
		if (sceClibStrncmp(name, "spoofed_version", 15) == 0)
		{
			if (string != NULL)
			{
				load_config_user();
				build_version_string(config.spoofed_version ? config.spoofed_version : SPOOF_VERSION, string, length);
			}
		}

		return 0;
	}

	return TAI_CONTINUE(int, g_sceRegMgrGetKeyStr_SceSystemSettingsCore_hook, category, name, string, length);
}

#define IS_DIGIT(i) ((i) >= '0' && (i) <= '9')
static tai_hook_ref_t g_sceRegMgrSetKeyStr_SceSystemSettingsCore_hook;
static int sceRegMgrSetKeyStr_SceSystemSettingsCore_patched(const char* category, const char* name, const char* string, int length)
{
	if (sceClibStrncmp(category, "/CONFIG/HENKAKU", 15) == 0)
	{
		if (sceClibStrncmp(name, "spoofed_version", 15) == 0)
		{
			if (string != NULL)
			{
				if (IS_DIGIT(string[0]) && string[1] == '.' && IS_DIGIT(string[2]) && IS_DIGIT(string[3]))
				{
					char a = string[0] - '0';
					char b = string[2] - '0';
					char c = string[3] - '0';
					char d = IS_DIGIT(string[4]) ? string[4] - '0' : '\0';
					config.spoofed_version = ((a << 24) | (b << 20) | (c << 16) | (d << 12));
					save_config_user();
					henkaku_reload_config();
				}
			}
		}

		return 0;
	}

	return TAI_CONTINUE(int, g_sceRegMgrSetKeyStr_SceSystemSettingsCore_hook, category, name, string, length);
}
#undef IS_DIGIT

// TODO: This structure is wrong, please fix!
typedef struct
{
	int         size;
	const char* name;
	int         type;
	int         unk;
} SceRegMgrKeysInfo;

static tai_hook_ref_t g_sceRegMgrGetKeysInfo_SceSystemSettingsCore_hook;
static int sceRegMgrGetKeysInfo_SceSystemSettingsCore_patched(const char* category, SceRegMgrKeysInfo* info, int unk)
{
	if (sceClibStrncmp(category, "/CONFIG/HENKAKU", 15) == 0)
	{
		if (info)
		{
			if (sceClibStrncmp(info->name, "spoofed_version", 15) == 0)
			{
				info->type = 0x00030001; // size 3 bytes, type string
			}
			else
			{
				info->type = 0x00040000; // size 4 bytes, type integer
			}
		}

		return 0;
	}

	return TAI_CONTINUE(int, g_sceRegMgrGetKeysInfo_SceSystemSettingsCore_hook, category, info, unk);
}

static int (*g_OnButtonEventIduSettings_hook)(const char* id, int a2, void* a3);
static int OnButtonEventIduSettings_patched(const char* id, int a2, void* a3)
{
	if (sceClibStrncmp(id, "id_reload_taihen_config", 23) == 0)
	{
		return taiReloadConfig();
	}
	else if (sceClibStrncmp(id, "id_reboot_device", 16) == 0)
	{
		return scePowerRequestColdReset();
	}
	else if (sceClibStrncmp(id, "id_unlink_memory_card", 21) == 0)
	{
		uint8_t buf[0x100];
		sceClibMemset(buf, 0, sizeof(buf));

		int ret;
		if ((ret = _vshIoMount(SCE_VSH_MOUNT_UX0, NULL, 2, buf)) < 0)
		{
			LOG("_vshIoMount failed with 0x%08X", ret);
			if (ret != SCE_ERROR_ERRNO_EEXIST) // already mounted
			{
				return ret;
			}
		}
		if ((ret = sceIoRemove("ux0:id.dat")) < 0)
		{
			LOG("sceIoRemove failed with 0x%08X", ret);
			if (ret != SCE_ERROR_ERRNO_ENOENT) // no entry
			{
				return ret;
			}
		}

		return 0;
	}

	// TODO: This will probably never hit..?
	return g_OnButtonEventIduSettings_hook(id, a2, a3);
}

// TODO: This is hideous, can we make it better?
static tai_hook_ref_t g_ScePafToplevel_F5354FEF_SceSettings_hook;
static int ScePafToplevel_F5354FEF_SceSettings_patched(void* a1, int a2, uint32_t* funcs)
{
	int res = TAI_CONTINUE(int, g_ScePafToplevel_F5354FEF_SceSettings_hook, a1, a2, funcs);
	char* plugin = (char*)((uint32_t*)a1)[1];
	if (sceClibStrncmp(plugin, "idu_settings_plugin", 19) == 0)
	{
		if (funcs[6] != (uint32_t)&OnButtonEventIduSettings_patched)
		{
			g_OnButtonEventIduSettings_hook = (void*)funcs[6];
			funcs[6] = (uint32_t)&OnButtonEventIduSettings_patched;
		}
	}
	return res;
}

// TODO: Hardcoding a position to use strncmp on is a bit stupid...
// TODO: And so is replacing IDU Settings, we should ideally keep both HENkaku Settings and IDU Settings functional.
// A possibility is to replace the System Update XML, given that HENkaku Settings replaces its entry.
// However, this was the original behaviour, and apparently, it caused some issues. (which?)
static tai_hook_ref_t g_ScePafMisc_19FE55A8_SceSettings_hook;
static int ScePafMisc_19FE55A8_SceSettings_patched(int a1, char* xml_buf, int xml_size, int a4)
{
	if ((82 + 22) < xml_size && sceClibStrncmp(xml_buf + 82, "system_settings_plugin", 22) == 0)
	{
		if (_binary_system_settings_xml_start != NULL)
		{
			xml_buf  = _binary_system_settings_xml_start;
			xml_size = _binary_system_settings_xml_size;
		}
	}
	else if ((79 + 19) < xml_size && sceClibStrncmp(xml_buf + 79, "idu_settings_plugin", 19) == 0)
	{
		xml_buf  = (void*)&_binary_henkaku_settings_xml_start;
		xml_size = (int)&_binary_henkaku_settings_xml_size;
	}

	return TAI_CONTINUE(int, g_ScePafMisc_19FE55A8_SceSettings_hook, a1, xml_buf, xml_size, a4);
}

static tai_hook_ref_t g_ScePafToplevel_19CEFDA7_SceSystemSettingsCore_hook;
static wchar_t* ScePafToplevel_19CEFDA7_SceSystemSettingsCore_patched(void* arg, char** msg)
{
	language_container_t* language_container;
	int language = -1;
	sceRegMgrGetKeyInt("/CONFIG/SYSTEM", "language", &language);
	switch (language)
	{
	case SCE_SYSTEM_PARAM_LANG_JAPANESE:      language_container = &language_japanese;      break;
	case SCE_SYSTEM_PARAM_LANG_ENGLISH_US:    language_container = &language_english_us;    break;
	case SCE_SYSTEM_PARAM_LANG_FRENCH:        language_container = &language_french;        break;
	case SCE_SYSTEM_PARAM_LANG_SPANISH:       language_container = &language_spanish;       break;
	case SCE_SYSTEM_PARAM_LANG_GERMAN:        language_container = &language_german;        break;
	case SCE_SYSTEM_PARAM_LANG_ITALIAN:       language_container = &language_italian;       break;
	case SCE_SYSTEM_PARAM_LANG_DUTCH:         language_container = &language_dutch;         break;
	case SCE_SYSTEM_PARAM_LANG_PORTUGUESE_PT: language_container = &language_portuguese_pt; break;
	case SCE_SYSTEM_PARAM_LANG_RUSSIAN:       language_container = &language_russian;       break;
	case SCE_SYSTEM_PARAM_LANG_KOREAN:        language_container = &language_korean;        break;
	case SCE_SYSTEM_PARAM_LANG_CHINESE_T:     language_container = &language_chinese_t;     break;
	case SCE_SYSTEM_PARAM_LANG_CHINESE_S:     language_container = &language_chinese_s;     break;
	case SCE_SYSTEM_PARAM_LANG_FINNISH:       language_container = &language_finnish;       break;
	case SCE_SYSTEM_PARAM_LANG_SWEDISH:       language_container = &language_swedish;       break;
	case SCE_SYSTEM_PARAM_LANG_DANISH:        language_container = &language_danish;        break;
	case SCE_SYSTEM_PARAM_LANG_NORWEGIAN:     language_container = &language_norwegian;     break;
	case SCE_SYSTEM_PARAM_LANG_POLISH:        language_container = &language_polish;        break;
	case SCE_SYSTEM_PARAM_LANG_PORTUGUESE_BR: language_container = &language_portuguese_br; break;
	case SCE_SYSTEM_PARAM_LANG_ENGLISH_GB:    language_container = &language_english_gb;    break;
	case SCE_SYSTEM_PARAM_LANG_TURKISH:       language_container = &language_turkish;       break;
	default:                                  language_container = &language_english_us;    break;
	}

	if (msg && sceClibStrncmp(*msg, "msg_", 4) == 0)
	{
		#define LANGUAGE_ENTRY(name) \
			else if (sceClibStrncmp(*msg, #name, sizeof(#name)) == 0) \
			{ \
				return language_container->name; \
			}

		if (0) {}
		LANGUAGE_ENTRY(msg_henkaku_settings)
		LANGUAGE_ENTRY(msg_enable_psn_spoofing)
		LANGUAGE_ENTRY(msg_enable_unsafe_homebrew)
		LANGUAGE_ENTRY(msg_unsafe_homebrew_description)
		LANGUAGE_ENTRY(msg_enable_version_spoofing)
		LANGUAGE_ENTRY(msg_spoofed_version)
		LANGUAGE_ENTRY(msg_button_behavior)
		LANGUAGE_ENTRY(msg_button_enter)
		LANGUAGE_ENTRY(msg_button_cancel)
		LANGUAGE_ENTRY(msg_reload_taihen_config)
		LANGUAGE_ENTRY(msg_reload_taihen_config_success)
		LANGUAGE_ENTRY(msg_reboot_device)
		LANGUAGE_ENTRY(msg_content_downloader)
		LANGUAGE_ENTRY(msg_unlink_memory_card)
		LANGUAGE_ENTRY(msg_unlink_memory_card_success)
		LANGUAGE_ENTRY(msg_unlink_memory_card_error)

		#undef LANGUAGE_ENTRY
	}

	return TAI_CONTINUE(wchar_t*, g_ScePafToplevel_19CEFDA7_SceSystemSettingsCore_hook, arg, msg);
}

static SceUID g_system_settings_core_modid = SCE_UID_INVALID_UID;
static tai_hook_ref_t g_sceKernelLoadStartModule_SceSettings_hook;
static SceUID sceKernelLoadStartModule_SceSettings_patched(char* path, SceSize args, void* argp, int flags, SceKernelLoadModuleOption* option, int* status)
{
	SceUID ret = TAI_CONTINUE(SceUID, g_sceKernelLoadStartModule_SceSettings_hook, path, args, argp, flags, option, status);
	if (ret >= 0 && sceClibStrncmp(path, "vs0:app/NPXS10015/system_settings_core.suprx", 44) == 0)
	{
		g_system_settings_core_modid = ret;

		g_hooks[7] = taiHookFunctionImport(&g_ScePafToplevel_F5354FEF_SceSettings_hook, 
		                                   "SceSettings", 
		                                   0x4D9A9DD0, // ScePafToplevel
		                                   0xF5354FEF, // _ZN3paf6Plugin12SetInterfaceEiPv [paf::Plugin::SetInterface(int, void*)]
		                                   ScePafToplevel_F5354FEF_SceSettings_patched);

		g_hooks[8] = taiHookFunctionImport(&g_ScePafMisc_19FE55A8_SceSettings_hook, 
		                                   "SceSettings", 
		                                   0x3D643CE8, // ScePafMisc
		                                   0x19FE55A8, // _ZN3paf7MemFile4OpenEPKvjPi [paf::MemFile::Open(void const*, unsigned int, int*)]
		                                   ScePafMisc_19FE55A8_SceSettings_patched);

		g_hooks[9] = taiHookFunctionImport(&g_sceRegMgrGetKeyInt_SceSystemSettingsCore_hook, 
		                                   "SceSystemSettingsCore", 
		                                   0xC436F916, // SceRegMgr
		                                   0x16DDF3DC, // sceRegMgrGetKeyInt
		                                   sceRegMgrGetKeyInt_SceSystemSettingsCore_patched);

		g_hooks[10] = taiHookFunctionImport(&g_sceRegMgrSetKeyInt_SceSystemSettingsCore_hook, 
		                                    "SceSystemSettingsCore", 
		                                    0xC436F916, // SceRegMgr
		                                    0xD72EA399, // sceRegMgrSetKeyInt
		                                    sceRegMgrSetKeyInt_SceSystemSettingsCore_patched);

		g_hooks[11] = taiHookFunctionImport(&g_sceRegMgrGetKeyStr_SceSystemSettingsCore_hook, 
		                                    "SceSystemSettingsCore", 
		                                    0xC436F916, // SceRegMgr
		                                    0xE188382F, // sceRegMgrGetKeyStr
		                                    sceRegMgrGetKeyStr_SceSystemSettingsCore_patched);

		g_hooks[12] = taiHookFunctionImport(&g_sceRegMgrSetKeyStr_SceSystemSettingsCore_hook, 
		                                    "SceSystemSettingsCore", 
		                                    0xC436F916, // SceRegMgr
		                                    0x41D320C5, // sceRegMgrSetKeyStr
		                                    sceRegMgrSetKeyStr_SceSystemSettingsCore_patched);

		g_hooks[13] = taiHookFunctionImport(&g_sceRegMgrGetKeysInfo_SceSystemSettingsCore_hook, 
		                                    "SceSystemSettingsCore", 
		                                    0xC436F916, // SceRegMgr
		                                    0x58421DD1, // sceRegMgrGetKeysInfo
		                                    sceRegMgrGetKeysInfo_SceSystemSettingsCore_patched);

		g_hooks[14] = taiHookFunctionImport(&g_ScePafToplevel_19CEFDA7_SceSystemSettingsCore_hook, 
		                                    "SceSystemSettingsCore", 
		                                    0x4D9A9DD0, // ScePafToplevel
		                                    0x19CEFDA7, // _ZNK3paf6Plugin9GetStringERKNS_7IDParamE [paf::Plugin::GetString(paf::IDParam const&) const]
		                                    ScePafToplevel_19CEFDA7_SceSystemSettingsCore_patched);

		// Needs to be done here, otherwise ScePaf isn't loaded yet.
		// TODO: See if we can use the library id directly.
		// NOTE: If this fails, the Settings app will crash when this is called.
		// This is should never happen! But it may be worth guarding against it.
		// Alternatively, weakly linking to ScePafStdc may be an option?
		taiGetModuleExportFunc("ScePaf", 0xA7D28DAE, 0xFC5CD359, (uintptr_t*)&sce_paf_operator_new);
		LOG("sce_paf_operator_new is %p", sce_paf_operator_new);
	}

	return ret;
}

static tai_hook_ref_t g_sceKernelStopUnloadModule_SceSettings_hook;
static int sceKernelStopUnloadModule_SceSettings_patched(SceUID modid, SceSize args, void* argp, int flags, SceKernelUnloadModuleOption* option, int* status)
{
	if (modid == g_system_settings_core_modid)
	{
		g_system_settings_core_modid = SCE_UID_INVALID_UID;
		
		if (g_hooks[7] >= 0) taiHookRelease(g_hooks[7], g_ScePafToplevel_F5354FEF_SceSettings_hook);
		if (g_hooks[8] >= 0) taiHookRelease(g_hooks[8], g_ScePafMisc_19FE55A8_SceSettings_hook);
		if (g_hooks[9] >= 0) taiHookRelease(g_hooks[9], g_sceRegMgrGetKeyInt_SceSystemSettingsCore_hook);
		if (g_hooks[10] >= 0) taiHookRelease(g_hooks[10], g_sceRegMgrSetKeyInt_SceSystemSettingsCore_hook);
		if (g_hooks[11] >= 0) taiHookRelease(g_hooks[11], g_sceRegMgrGetKeyStr_SceSystemSettingsCore_hook);
		if (g_hooks[12] >= 0) taiHookRelease(g_hooks[12], g_sceRegMgrSetKeyStr_SceSystemSettingsCore_hook);
		if (g_hooks[13] >= 0) taiHookRelease(g_hooks[13], g_sceRegMgrGetKeysInfo_SceSystemSettingsCore_hook);
		if (g_hooks[14] >= 0) taiHookRelease(g_hooks[14], g_ScePafToplevel_19CEFDA7_SceSystemSettingsCore_hook);
	}

	return TAI_CONTINUE(int, g_sceKernelStopUnloadModule_SceSettings_hook, modid, args, argp, flags, option, status);
}

int module_start(SceSize args, const void* argp)
{
	UNUSED_PARAM(args);
	UNUSED_PARAM(argp);

	// This fills `g_hooks` with `SCE_UID_INVALID_UID`.
	sceClibMemset(g_hooks, 0xFF, sizeof(g_hooks));

	tai_module_info_t info;
	LOG("loading HENkaku config for user");
	load_config_user();

	sceClibMemset(&info, 0, sizeof(tai_module_info_t));
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfo("SceSettings", &info) >= 0)
	{
		LOG("SceSettings dbg_fingerprint: 0x%08X\n", info.module_nid);

		// This is needed because some options were added in later firmwares.
		// - 'Theme & Background' was added in 3.30.
		// - 'Accessibility' was added in 3.50.
		// An alternative would be to dynamically find and patch the 'System Update' entry.
		SceKernelSystemSwVersion fwinfo;
		sceClibMemset(&fwinfo, 0, sizeof(SceKernelSystemSwVersion));
		fwinfo.size = sizeof(SceKernelSystemSwVersion);
		_vshSblGetSystemSwVersion(&fwinfo);
		LOG("System firmware version: 0x%08X\n", fwinfo.version);
		if (fwinfo.version >= 0x03500000)
		{
			// Valid for 3.50 - 3.74
			_binary_system_settings_xml_start = (void*)&_binary_system_settings_350_xml_start;
			_binary_system_settings_xml_size  = (int)&_binary_system_settings_350_xml_size;
		}
		else if (fwinfo.version >= 0x03300000)
		{
			// Valid for 3.30 - 3.36
			_binary_system_settings_xml_start = (void*)&_binary_system_settings_330_xml_start;
			_binary_system_settings_xml_size  = (int)&_binary_system_settings_330_xml_size;
		}

		g_hooks[0] = taiHookFunctionImport(&g_sceKernelLoadStartModule_SceSettings_hook, 
		                                   "SceSettings", 
		                                   0xCAE9ACE6, // SceLibKernel
		                                   0x2DCC4AFA, // sceKernelLoadStartModule
		                                   sceKernelLoadStartModule_SceSettings_patched);
		LOG("sceKernelLoadStartModule hook: %x", g_hooks[0]);

		g_hooks[1] = taiHookFunctionImport(&g_sceKernelStopUnloadModule_SceSettings_hook, 
		                                   "SceSettings", 
		                                   0xCAE9ACE6, // SceLibKernel
		                                   0x2415F8A4, // sceKernelStopUnloadModule
		                                   sceKernelStopUnloadModule_SceSettings_patched);
		LOG("sceKernelStopUnloadModule hook: %x", g_hooks[1]);

		// TODO: Only hook this for CEX builds?
		// If we do that, we can reuse `g_hooks[2]` and `g_sceKernelGetSystemSwVersion_SceSettings_hook`
		// (which would need to be renamed) for both the CEX hook, and the DEX/TOOL hook.
		g_hooks[2] = taiHookFunctionImport(&g_sceKernelGetSystemSwVersion_SceSettings_hook, 
		                                   "SceSettings", 
		                                   0xEAED1616, // SceModulemgr
		                                   0x5182E212, // sceKernelGetSystemSwVersion
		                                   sceKernelGetSystemSwVersion_SceSettings_patched);
		LOG("sceKernelGetSystemSwVersion hook: %x", g_hooks[2]);

		// These hooks are needed to fix the version string for DEX/TOOL SceSettings builds.
		switch (info.module_nid)
		{
		// All CEX (and CFT) SceSettings builds use `sceKernelGetSystemSwVersion` to get the version string.
		// Therefore, we will simply abort if we encounter a CEX SceShell NID.
		case 0x0D75AC50: // 3.30 CEX SceSettings
		case 0xC2F19B5D: // 3.35 CEX SceSettings
		case 0xFFD7500F: // 3.36 CEX SceSettings
		case 0x11C29BED: // 3.50 CEX SceSettings
		case 0x4D6927BC: // 3.51 CEX SceSettings
		case 0xF8501C94: // 3.52 CEX SceSettings
		case 0x13B4C016: // 3.65 CEX SceSettings
		case 0x1DE1C1EF: // 3.65 CFT SceSettings
			break;

		case 0xDDBDCA22: // 3.65 DEX SceSettings
		{
			g_hooks[15] = taiHookFunctionOffset(&g_get_version_string_hook,
			                                    info.modid,
			                                    0,         // segidx
			                                    0x02F080,  // offset
			                                    1,         // thumb
		        	                            get_version_string_patched);
			break;
		}

		case 0x00994D5D: // 3.65 TOOL SceSettings
		{
			g_hooks[15] = taiHookFunctionOffset(&g_get_version_string_hook,
			                                    info.modid,
			                                    0,         // segidx
			                                    0x02F19C,  // offset
			                                    1,         // thumb
		        	                            get_version_string_patched);
			break;
		}

		default:
		{
			g_hooks[15] = SCE_UID_INVALID_UID;
			LOG("SceSettings NID 0x%08X not recognized, skipping version string patches", info.module_nid);
			break;
		}
		}
	}

	g_hooks[3] = SCE_UID_INVALID_UID;
	g_hooks[4] = SCE_UID_INVALID_UID;
	g_hooks[5] = SCE_UID_INVALID_UID;

	sceClibMemset(&info, 0, sizeof(tai_module_info_t));
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfo("SceShell", &info) >= 0)
	{
		LOG("SceShell dbg_fingerprint: 0x%08X\n", info.module_nid);

		if (config.use_psn_spoofing)
		{
			// we don't have a nice clean way of doing PSN spoofing (update prompt disable) so 
			// we are stuck with hard coding offsets. Since module NID is different for each 
			// version and CEX/DEX/TOOL unit, this should allow us to specify different 
			// offsets.
			switch (info.module_nid)
			{
			case 0x2734F75F: // 3.30 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x33E0C2,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x355DAE,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x300470,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0xB335EA6B: // 3.35 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x33EC2A,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x356AB6,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x300FD8,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x1AF19E7A: // 3.36 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x33EE62,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x356CEE,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x301210,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0xE1FF69B5: // 3.50 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x362ECC,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37AFBE,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x324314,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x8C011876: // 3.51 CEX SceShell
			case 0x10FDF502: // 3.52 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x362F30,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37B022,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x324378,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x8978D25D: // 3.55 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x363968,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37BA5A,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x324DB0,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x9F367BFC: // 3.57 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x3637CC,  // offset
				                                   1,         // thumb
				                                   update_check_patched);
				
				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37B8BE,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);
				
				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x324C14,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x0552F692: // 3.60 CEX SceShell
			case 0x532155E5: // 3.61 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x363DE8,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37BEDA,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x325230,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0xEAB89D5C: // 3.60 DEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x35A830,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x372832,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x31BC78,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x6CB01295: // 3.60 TOOL SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x12C882,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x36DF3E,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x317384,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0xBB4B0A3E: // 3.63 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x363E84,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37BF76,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x3252CC,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x5549BF1F: // 3.65 CEX SceShell
			case 0x34B4D82E: // 3.67 CEX SceShell
			case 0x12DAC0F3: // 3.68 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x36422C,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37C31E,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x325674,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x587F9CED: // 3.65 DEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x35AC74,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x372C76,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x31C0BC,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0xE6A02F2B: // 3.65 TOOL SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x12C8DA,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x36E3AA,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x3177F0,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x768E59EF: // 3.65 CFT SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x364490,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37C582,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x3258D8,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				break;
			}
			case 0x0703C828: // 3.69 CEX SceShell
        	case 0x2053B5A5: // 3.70 CEX SceShell
        	case 0xF476E785: // 3.71 CEX SceShell
        	case 0x939FFBE9: // 3.72 CEX SceShell
        	case 0x734D476A: // 3.73 CEX SceShell
        	case 0x51CB6207: // 3.74 CEX SceShell
			{
				g_hooks[3] = taiHookFunctionOffset(&g_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x36423C,  // offset
				                                   1,         // thumb
				                                   update_check_patched);

				g_hooks[4] = taiHookFunctionOffset(&g_game_update_check_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x37C32E,  // offset
				                                   1,         // thumb
				                                   game_update_check_patched);

				g_hooks[5] = taiHookFunctionOffset(&g_passphrase_decrypt_hook,
				                                   info.modid,
				                                   0,         // segidx
				                                   0x325684,  // offset
				                                   1,         // thumb
				                                   passphrase_decrypt_patched);
				
				break;
			}
			default:
			{
				LOG("SceShell NID 0x%08X not recognized, skipping PSN spoofing patches", info.module_nid);
				break;
			}
			}
		}
		else
		{
			LOG("skipping psn spoofing patches");
		}

		// add patch to skip id.dat checks (only works if plugin loads before start)
		g_hooks[6] = taiHookFunctionImport(&g_vshNpDrmIsLooseAccountBind_SceShell_hook, 
		                                   "SceShell", 
		                                   0x35C5ACD4, // SceVshBridge
		                                   0x333875AB, // vshNpDrmIsLooseAccountBind
		                                   vshNpDrmIsLooseAccountBind_SceShell_patched);
	}

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, const void* argp)
{
	UNUSED_PARAM(args);
	UNUSED_PARAM(argp);

	LOG("stopping module");

	// free hooks that didn't fail
	if (g_hooks[0] >= 0) taiHookRelease(g_hooks[0], g_sceKernelLoadStartModule_SceSettings_hook);
	if (g_hooks[1] >= 0) taiHookRelease(g_hooks[1], g_sceKernelStopUnloadModule_SceSettings_hook);
	if (g_hooks[2] >= 0) taiHookRelease(g_hooks[2], g_sceKernelGetSystemSwVersion_SceSettings_hook);
	if (g_hooks[3] >= 0) taiHookRelease(g_hooks[3], g_update_check_hook);
	if (g_hooks[4] >= 0) taiHookRelease(g_hooks[4], g_game_update_check_hook);
	if (g_hooks[5] >= 0) taiHookRelease(g_hooks[5], g_passphrase_decrypt_hook);
	if (g_hooks[6] >= 0) taiHookRelease(g_hooks[6], g_vshNpDrmIsLooseAccountBind_SceShell_hook);
	if (g_hooks[7] >= 0) taiHookRelease(g_hooks[7], g_ScePafToplevel_F5354FEF_SceSettings_hook);
	if (g_hooks[8] >= 0) taiHookRelease(g_hooks[8], g_ScePafMisc_19FE55A8_SceSettings_hook);
	if (g_hooks[9] >= 0) taiHookRelease(g_hooks[9], g_sceRegMgrGetKeyInt_SceSystemSettingsCore_hook);
	if (g_hooks[10] >= 0) taiHookRelease(g_hooks[10], g_sceRegMgrSetKeyInt_SceSystemSettingsCore_hook);
	if (g_hooks[11] >= 0) taiHookRelease(g_hooks[11], g_sceRegMgrGetKeyStr_SceSystemSettingsCore_hook);
	if (g_hooks[12] >= 0) taiHookRelease(g_hooks[12], g_sceRegMgrSetKeyStr_SceSystemSettingsCore_hook);
	if (g_hooks[13] >= 0) taiHookRelease(g_hooks[13], g_sceRegMgrGetKeysInfo_SceSystemSettingsCore_hook);
	if (g_hooks[14] >= 0) taiHookRelease(g_hooks[14], g_ScePafToplevel_19CEFDA7_SceSystemSettingsCore_hook);
	if (g_hooks[15] >= 0) taiHookRelease(g_hooks[15], g_get_version_string_hook);

	return SCE_KERNEL_STOP_SUCCESS;
}
