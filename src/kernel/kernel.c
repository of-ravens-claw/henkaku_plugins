#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>

#include <stdio.h>
#include <string.h>
#include <taihen.h>

#include "henkaku.h"
#include "config.h"

#define OFFSET_PATCH_ARG    (0xA8)
#define OFFSET_PATCH_AUTHID (0x98)

typedef struct
{
	uint32_t magic;                 /* 53434500 = SCE\0 */
	uint32_t version;               /* header version 3*/
	uint16_t sdk_type;              /* */
	uint16_t header_type;           /* 1 self, 2 unknown, 3 pkg */
	uint32_t metadata_offset;       /* metadata offset */
	uint64_t header_len;            /* self header length */
	uint64_t elf_filesize;          /* ELF file length */
	uint64_t self_filesize;         /* SELF file length */
	uint64_t unknown;               /* UNKNOWN */
	uint64_t self_offset;           /* SELF offset */
	uint64_t appinfo_offset;        /* app info offset */
	uint64_t elf_offset;            /* ELF #1 offset */
	uint64_t phdr_offset;           /* program header offset */
	uint64_t shdr_offset;           /* section header offset */
	uint64_t section_info_offset;   /* section info offset */
	uint64_t sceversion_offset;     /* version offset */
	uint64_t controlinfo_offset;    /* control info offset */
	uint64_t controlinfo_size;      /* control info size */
	uint64_t padding;               
} __attribute__((packed)) self_header_t;

typedef struct
{
	uint64_t authid;                /* auth id */
	uint32_t vendor_id;             /* vendor id */
	uint32_t self_type;             /* app type */
	uint64_t padding;               /* UNKNOWN */
} __attribute__((packed)) app_info_t;

static henkaku_config_t config;

static SceUID g_hooks[6];

static tai_hook_ref_t g_sceSblAuthMgrAuthHeader_hook;
static int sceSblAuthMgrAuthHeader_patched(int ctx, const void* headers, size_t len, void* args)
{
	int ret = TAI_CONTINUE(int, g_sceSblAuthMgrAuthHeader_hook, ctx, headers, len, args);
	if (len >= sizeof(self_header_t) && len >= sizeof(app_info_t))
	{
		self_header_t* self = (self_header_t*)headers;
		if (self->appinfo_offset <= len - sizeof(app_info_t))
		{
			app_info_t* info = (app_info_t*)(headers + self->appinfo_offset);
			LOG("authid: 0x%llx\n", info->authid);
			if (ret < 0 && config.allow_unsafe_hb)
			{
				// Homebrew usually returns 0x800F0624
				// Games designed for a newer firmware seem to return 0x800F0B37 (sample size of one, so not certain.)

				//LOG("is homebrew!");
				LOG("maybe homebrew! ret 0x%08X", ret);
				if ((info->authid & 0xFFFFFFFFFFFFFFFCLL) == 0x2F00000000000000LL)
				{
					if (info->authid & 1)
					{
						// we just give extended permissions
						*(uint32_t*)(args + OFFSET_PATCH_ARG) = 0x40;
					}
				}
				else
				{
					// we give authid + extended permissions
					*(uint32_t*)(args + OFFSET_PATCH_ARG) = 0x40;
					*(uint64_t*)(args + OFFSET_PATCH_AUTHID) = info->authid;
				}
			}
		}
	}
	return ret;
}

static tai_hook_ref_t g_sceKernelSysrootCheckRemapCodeForUser_hook;
static int sceKernelSysrootCheckRemapCodeForUser_patched(void)
{
	TAI_CONTINUE(int, g_sceKernelSysrootCheckRemapCodeForUser_hook);
	return 1;
}

static tai_hook_ref_t g_sceKernelCheckOpenVMDomain_hook;
static int sceKernelCheckOpenVMDomain_patched(void)
{
	TAI_CONTINUE(int, g_sceKernelCheckOpenVMDomain_hook);
	return 0;
}

static tai_hook_ref_t g_sceSblACMgrIsSystemProgram_hook;
static int sceSblACMgrIsSystemProgram_patched(void)
{
	// this function may be called in the process of looping
	// see: https://github.com/yifanlu/taiHEN/issues/12
	// for now, we mark this as a FIXME and do this check manually
	if (g_sceSblACMgrIsSystemProgram_hook)
	{
		TAI_CONTINUE(int, g_sceSblACMgrIsSystemProgram_hook);
	}
	return 1;
}

static tai_hook_ref_t g_sceKernelGetSystemSwVersion_hook;
static int sceKernelGetSystemSwVersion_patched(SceKernelSystemSwVersion* info)
{
	int ret;
	int ver_major;
	int ver_minor;
	ret = TAI_CONTINUE(int, g_sceKernelGetSystemSwVersion_hook, info);
	info->version = config.spoofed_version;
	ver_major = ((config.spoofed_version >> 24) & 0xF) + 10 * (config.spoofed_version >> 28);
	ver_minor = ((config.spoofed_version >> 16) & 0xF) + 10 * ((config.spoofed_version >> 20) & 0xF);
	snprintf(info->versionString, 16, "%d.%02d", ver_major, ver_minor);
	return ret;
}

static tai_hook_ref_t g_sceSblUsGetSpkgInfo_hook;
static int sceSblUsGetSpkgInfo_patched(int r0, uintptr_t out)
{
	int ver;
	int ret;
	ret = TAI_CONTINUE(int, g_sceSblUsGetSpkgInfo_hook, r0, out);
	if (r0 == 1 || r0 == 9 || r0 == 10 || r0 == 21 || r0 == 22)
	{
		ver = config.spoofed_version;
		ksceKernelCopyToUser((void*)(out + 4), &ver, 4);
	}
	return ret;
}

static int load_config_kernel(SceSize args, void* argp)
{
	UNUSED_PARAM(args);
	UNUSED_PARAM(argp);

	SceUID fd;
	int rd;
	fd = ksceIoOpen(CONFIG_PATH, SCE_O_RDONLY, 0);
	if (fd < 0)
	{
		fd = ksceIoOpen(OLD_CONFIG_PATH, SCE_O_RDONLY, 0);
	}
	if (fd >= 0)
	{
		rd = ksceIoRead(fd, &config, sizeof(config));
		ksceIoClose(fd);
		if (rd == sizeof(config))
		{
			if (config.magic == HENKAKU_CONFIG_MAGIC)
			{
				if (config.version >= 0)
				{
					return 0;
				}
				else
				{
					LOG("config version too old");
				}
			}
			else
			{
				LOG("config incorrect magic: 0x%08X", config.magic);
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

// user export
int henkaku_reload_config(void)
{
	int state;
	int tid;
	int ret;
	ENTER_SYSCALL(state);
	tid = ksceKernelCreateThread("configwrite", load_config_kernel, 64, 0x1000, 0, 0, NULL);
	LOG("ksceKernelCreateThread: 0x%08X", tid);
	ret = ksceKernelStartThread(tid, 0, NULL);
	LOG("ksceKernelStartThread: 0x%08X", ret);
	ksceKernelWaitThreadEnd(tid, &ret, NULL);
	ksceKernelDeleteThread(tid);
	EXIT_SYSCALL(state);
	return ret;
}

int module_start(SceSize args, const void* argp)
{
	UNUSED_PARAM(args);
	UNUSED_PARAM(argp);

	memset(g_hooks, 0xFF, sizeof(g_hooks));

	LOG("loading HENkaku config for kernel");
	load_config_kernel(0, NULL);

	// this hook enables extended permissions for unsafe homebrew + blocking unsafe homebrew if requested
	g_hooks[0] = taiHookFunctionImportForKernel(KERNEL_PID, 
	                                            &g_sceSblAuthMgrAuthHeader_hook, 
	                                            "SceKernelModulemgr", 
	                                            0x7ABF5135, // SceSblAuthMgrForKernel
	                                            0xF3411881, // sceSblAuthMgrAuthHeader
	                                            sceSblAuthMgrAuthHeader_patched);
	LOG("sceSblAuthMgrAuthHeader hook: 0x%08X", g_hooks[0]);
	
	// the next two hooks enable dynarec by patching a system check and a process check
	g_hooks[1] = taiHookFunctionExportForKernel(KERNEL_PID, 
	                                            &g_sceKernelSysrootCheckRemapCodeForUser_hook, 
	                                            "SceSysmem", 
	                                            0x3691DA45, // SceSysrootForKernel
	                                            0xF8769E86, // sceKernelSysrootCheckRemapCodeForUser
	                                            sceKernelSysrootCheckRemapCodeForUser_patched);
	LOG("sceKernelSysrootCheckRemapCodeForUser hook: 0x%08X", g_hooks[1]);

	// TODO: This seems like a bad thing to always hook..?
	g_hooks[2] = taiHookFunctionExportForKernel(KERNEL_PID, 
	                                            &g_sceKernelCheckOpenVMDomain_hook, 
	                                            "SceSysmem", 
	                                            0x63A519E5, // SceSysmemForKernel
	                                            0xD514BB56, // sceKernelCheckOpenVMDomain
	                                            sceKernelCheckOpenVMDomain_patched);
	if (g_hooks[2] < 0) // 3.63+
	{
		g_hooks[2] = taiHookFunctionExportForKernel(KERNEL_PID, 
		                                            &g_sceKernelCheckOpenVMDomain_hook, 
		                                            "SceSysmem", 
		                                            0x02451F0F, // SceSysmemForKernel
		                                            0x4E6D8BC3, // sceKernelCheckOpenVMDomain
		                                            sceKernelCheckOpenVMDomain_patched);
	}

	LOG("sceKernelCheckOpenVMDomain hook: 0x%08X", g_hooks[2]);

	// TODO: Also seems like a bad idea to hook this...
	// this hook patches an auth check in ScePower for enabling overclocking in safe homebrew
	g_sceSblACMgrIsSystemProgram_hook = 0;
	g_hooks[3] = taiHookFunctionImportForKernel(KERNEL_PID, 
	                                            &g_sceSblACMgrIsSystemProgram_hook, 
	                                            "ScePower", 
	                                            0x9AD8E213, // SceSblACMgrForDriver
	                                            0x8612B243, // sceSblACMgrIsSystemProgram
	                                            sceSblACMgrIsSystemProgram_patched);
	LOG("sceSblACMgrIsSystemProgram hook: 0x%08X", g_hooks[3]);

	if (config.use_spoofed_version)
	{
		// this hook spoofs the system version for the API access
		g_hooks[4] = taiHookFunctionExportForKernel(KERNEL_PID, 
		                                            &g_sceKernelGetSystemSwVersion_hook, 
		                                            "SceKernelModulemgr", 
		                                            0xD4A60A52, // SceModulemgrForDriver
		                                            0x5182E212, // sceKernelGetSystemSwVersion
		                                            sceKernelGetSystemSwVersion_patched);
		LOG("sceKernelGetSystemSwVersion hook: 0x%08X", g_hooks[4]);

		// this hook spoofs the system version for internal access
		g_hooks[5] = taiHookFunctionExportForKernel(KERNEL_PID, 
		                                            &g_sceSblUsGetSpkgInfo_hook, 
		                                            "SceSblUpdateMgr", 
		                                            0x31406C49, // SceSblSsUpdateMgr
		                                            0x8E3EC2E1, // sceSblUsGetSpkgInfoForUser
		                                            sceSblUsGetSpkgInfo_patched);
		LOG("sceSblUsGetSpkgInfo hook: 0x%08X", g_hooks[5]);
	}
	else
	{
		LOG("skipping version spoofing");
	}

	if (args == 4 && argp != NULL)
	{
		SceUID shell_pid = *(SceUID*)argp;
		LOG("loading shell plugins");
		// normally this would be done automatically by taiHEN
		// but since our exploit runs AFTER SceShell is loaded, 
		// we have to do this manually
		taiLoadPluginsForTitleForKernel(shell_pid, "main", 0);
		LOG("shell plugins loaded");
	}

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, const void* argp)
{
	UNUSED_PARAM(args);
	UNUSED_PARAM(argp);
	
	if (g_hooks[0] >= 0) taiHookReleaseForKernel(g_hooks[0], g_sceSblAuthMgrAuthHeader_hook);
	if (g_hooks[1] >= 0) taiHookReleaseForKernel(g_hooks[1], g_sceKernelSysrootCheckRemapCodeForUser_hook);
	if (g_hooks[2] >= 0) taiHookReleaseForKernel(g_hooks[2], g_sceKernelCheckOpenVMDomain_hook);
	if (g_hooks[3] >= 0) taiHookReleaseForKernel(g_hooks[3], g_sceSblACMgrIsSystemProgram_hook);
	if (g_hooks[4] >= 0) taiHookReleaseForKernel(g_hooks[4], g_sceKernelGetSystemSwVersion_hook);
	if (g_hooks[5] >= 0) taiHookReleaseForKernel(g_hooks[5], g_sceSblUsGetSpkgInfo_hook);

	return SCE_KERNEL_STOP_SUCCESS;
}
