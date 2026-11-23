#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (__stdcall *cbtype)(char *what, int int1, int int2, char *str);
typedef int (__cdecl *FreeArcExtractFn)(cbtype callback, ...);

static double g_orig_mb = 0.0;
static double g_total_mb = 0.0;
static int g_last_pct = -1;
static unsigned int g_file_count = 0;

static double to_mb(int int1, int int2) {
    if (int1 > 0) return (double)int1;
    if (int2 > 0) return (double)(unsigned int)int2 / 1048576.0;
    return 0.0;
}

static int __stdcall arc_callback(char *what, int int1, int int2, char *str) {
    if (!what) return 0;

    if (strcmp(what, "origsize") == 0) {
        g_orig_mb = to_mb(int1, int2);
        printf("[UNARC-DLL] Archive unpacked size: %.1f MB\n", g_orig_mb);
        fflush(stdout);
    } else if (strcmp(what, "total") == 0 || strcmp(what, "compsize") == 0) {
        g_total_mb = to_mb(int1, int2);
    } else if (strcmp(what, "write") == 0) {
        if (g_orig_mb > 0.0) {
            double done = to_mb(int1, int2);
            int pct = (int)((done / g_orig_mb) * 100.0);
            if (pct > 100) pct = 100;
            if (pct < 0) pct = 0;
            if (pct != g_last_pct) {
                g_last_pct = pct;
                printf("Extracting: %d%%\n", pct);
                fflush(stdout);
            }
        }
    } else if (strcmp(what, "read") == 0) {
        if (g_orig_mb <= 0.0 && g_total_mb > 0.0) {
            double done = to_mb(int1, int2);
            int pct = (int)((done / g_total_mb) * 100.0);
            if (pct > 100) pct = 100;
            if (pct < 0) pct = 0;
            if (pct != g_last_pct) {
                g_last_pct = pct;
                printf("Extracting: %d%%\n", pct);
                fflush(stdout);
            }
        }
    } else if (strcmp(what, "progress") == 0) {
        if (int2 > 0) {
            int pct = (int)(((double)int1 / (double)int2) * 100.0);
            if (pct > 100) pct = 100;
            if (pct < 0) pct = 0;
            if (pct != g_last_pct) {
                g_last_pct = pct;
                printf("Extracting: %d%%\n", pct);
                fflush(stdout);
            }
        }
    } else if (strcmp(what, "filename") == 0) {
        g_file_count++;
        if (str && *str && (g_file_count <= 4 || (g_file_count % 30) == 0)) {
            printf("File: %s\n", str);
            fflush(stdout);
        }
    } else if (strcmp(what, "overwrite?") == 0) {
        return 'a';
    } else if (strcmp(what, "error") == 0) {
        if (str && *str) {
            printf("ERROR: %s\n", str);
            fflush(stdout);
        }
    }
    return 0;
}

static HANDLE create_cls_init_map(const char *name, SECURITY_ATTRIBUTES *sa, char **out_view) {
    HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, sa, PAGE_READWRITE, 0, 256, name);
    if (h) {
        char *v = (char *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 256);
        if (v) {
            memset(v, 0, 256);
            memcpy(v, "Global\\", 8);
        }
        *out_view = v;
    } else {
        *out_view = NULL;
    }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: unarc_host32.exe <work_dir> <unarc_args...>\n");
        return 100;
    }

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    const char *work_dir = argv[1];
    SetCurrentDirectoryA(work_dir);
    SetDllDirectoryA(work_dir);

    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;

    char *localView = NULL;
    char *globalView = NULL;
    HANDLE hLocalMap = create_cls_init_map("Init_MapFile_", &sa, &localView);
    HANDLE hGlobalMap = create_cls_init_map("Global\\Init_MapFile_", &sa, &globalView);

    printf("[UNARC-HOST] v8.1 | Init_MapFile_=%s | Global\\Init_MapFile_=%s\n",
           (hLocalMap && localView) ? "OK" : "FAIL",
           (hGlobalMap && globalView) ? "OK" : "FAIL");
    fflush(stdout);

    char dll_path[MAX_PATH * 2];
    _snprintf(dll_path, sizeof(dll_path) - 1, "%s\\unarc.dll", work_dir);
    dll_path[sizeof(dll_path) - 1] = '\0';

    HMODULE hmod = LoadLibraryA(dll_path);
    if (!hmod) {
        hmod = LoadLibraryA("unarc.dll");
    }
    if (!hmod) {
        printf("ERROR: Failed to load repack unarc.dll (Win32 error %lu)\n", GetLastError());
        fflush(stdout);
        if (localView) UnmapViewOfFile(localView);
        if (hLocalMap) CloseHandle(hLocalMap);
        if (globalView) UnmapViewOfFile(globalView);
        if (hGlobalMap) CloseHandle(hGlobalMap);
        return 101;
    }

    FreeArcExtractFn extract = (FreeArcExtractFn)GetProcAddress(hmod, "FreeArcExtract");
    if (!extract) {
        printf("ERROR: unarc.dll does not export FreeArcExtract\n");
        fflush(stdout);
        FreeLibrary(hmod);
        if (localView) UnmapViewOfFile(localView);
        if (hLocalMap) CloseHandle(hLocalMap);
        if (globalView) UnmapViewOfFile(globalView);
        if (hGlobalMap) CloseHandle(hGlobalMap);
        return 102;
    }

    char *a[24];
    int i;
    for (i = 0; i < 24; i++) a[i] = NULL;
    int n = argc - 2;
    if (n > 23) n = 23;
    for (i = 0; i < n; i++) {
        a[i] = argv[i + 2];
    }

    int rc = extract(
        arc_callback,
        a[0], a[1], a[2], a[3], a[4], a[5],
        a[6], a[7], a[8], a[9], a[10], a[11],
        a[12], a[13], a[14], a[15], a[16], a[17],
        a[18], a[19], a[20], a[21], a[22], a[23],
        NULL
    );

    FreeLibrary(hmod);
    if (localView) UnmapViewOfFile(localView);
    if (hLocalMap) CloseHandle(hLocalMap);
    if (globalView) UnmapViewOfFile(globalView);
    if (hGlobalMap) CloseHandle(hGlobalMap);

    if (rc != 0) {
        printf("ERROR: FreeArcExtract returned code %d (args:", rc);
        for (i = 0; i < n; i++) {
            if (a[i][0] == '-' && a[i][1] == 'p') printf(" -p***");
            else printf(" [%s]", a[i]);
        }
        printf(")\n");
        fflush(stdout);
        return (rc < 0) ? (-rc) : rc;
    }

    printf("Extracting: 100%%\n");
    fflush(stdout);
    return 0;
}
