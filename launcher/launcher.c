/*
 * RPM Encrypter Launcher — Unicode-path wrapper
 *
 * The Flet-built rpm-encrypter.exe embeds Python via the serious_python
 * Flutter plugin.  The embedded CPython initialisation crashes when the
 * executable sits inside a directory whose path contains non-ASCII
 * characters (Turkish ü/ö/ş/ç/ğ/İ, accented Latin, CJK, Cyrillic …).
 *
 * Strategy
 * --------
 * 1. If the current directory path is already ASCII-safe, launch
 *    rpm-encrypter.exe directly — zero overhead.
 *
 * 2. Otherwise, copy the entire application directory to an
 *    ASCII-safe location under %LOCALAPPDATA%\RPMEncrypter and
 *    launch from there.  A small marker file tracks whether the
 *    copy is up-to-date (based on the launcher's own timestamp).
 *    NTFS junctions/symlinks don't work because Flutter resolves
 *    them back to the physical (non-ASCII) path.
 *
 * Build (from a VS Developer Command Prompt, project root as CWD):
 *   rc  /fo launcher\launcher.res launcher\launcher.rc
 *   cl  /nologo /O2 launcher\launcher.c launcher\launcher.res ^
 *       /Fe"build\windows\RPM Encrypter.exe" ^
 *       /link /SUBSYSTEM:WINDOWS kernel32.lib user32.lib shell32.lib
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <shellapi.h>

/* ── helpers ─────────────────────────────────────────────────────── */

static BOOL PathHasNonAscii(const WCHAR *s)
{
    for (; *s; ++s)
        if (*s > 127)
            return TRUE;
    return FALSE;
}

/*  Recursively copy srcDir -> dstDir using SHFileOperationW.
 *  Creates dstDir if it doesn't exist.  Overwrites existing files. */
static BOOL CopyDirContents(const WCHAR *srcDir, const WCHAR *dstDir)
{
    /* SHFileOperationW needs double-null terminated strings */
    WCHAR src[MAX_PATH + 2];
    WCHAR dst[MAX_PATH + 2];

    wsprintfW(src, L"%s\\*", srcDir);
    src[lstrlenW(src) + 1] = L'\0';   /* double-null */

    wcscpy_s(dst, MAX_PATH + 2, dstDir);
    dst[lstrlenW(dst) + 1] = L'\0';

    CreateDirectoryW(dstDir, NULL);

    SHFILEOPSTRUCTW op;
    ZeroMemory(&op, sizeof(op));
    op.wFunc  = FO_COPY;
    op.pFrom  = src;
    op.pTo    = dst;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
              | FOF_NOCONFIRMMKDIR;

    return (SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted);
}

/* Write the launcher exe's own last-write time into a stamp file
   so we can detect when the user updates the application. */
static void WriteStamp(const WCHAR *stampPath, const WCHAR *launcherPath)
{
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExW(launcherPath, GetFileExInfoStandard, &attr))
        return;

    HANDLE h = CreateFileW(stampPath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, &attr.ftLastWriteTime, sizeof(FILETIME), &(DWORD){0}, NULL);
    CloseHandle(h);
}

/* Returns TRUE if the stamp file matches the launcher's timestamp. */
static BOOL StampMatches(const WCHAR *stampPath, const WCHAR *launcherPath)
{
    WIN32_FILE_ATTRIBUTE_DATA la;
    if (!GetFileAttributesExW(launcherPath, GetFileExInfoStandard, &la))
        return FALSE;

    HANDLE h = CreateFileW(stampPath, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    FILETIME stored;
    DWORD    read = 0;
    ReadFile(h, &stored, sizeof(FILETIME), &read, NULL);
    CloseHandle(h);

    if (read != sizeof(FILETIME)) return FALSE;
    return (stored.dwLowDateTime  == la.ftLastWriteTime.dwLowDateTime &&
            stored.dwHighDateTime == la.ftLastWriteTime.dwHighDateTime);
}

/* Delete a directory tree. */
static void NukeDir(const WCHAR *dir)
{
    WCHAR buf[MAX_PATH + 2];
    wcscpy_s(buf, MAX_PATH + 2, dir);
    buf[lstrlenW(buf) + 1] = L'\0';

    SHFILEOPSTRUCTW op;
    ZeroMemory(&op, sizeof(op));
    op.wFunc  = FO_DELETE;
    op.pFrom  = buf;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationW(&op);
}

/* ── entry point ─────────────────────────────────────────────────── */

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPWSTR lpCmdLine, int nCmdShow)
{
    WCHAR selfPath[MAX_PATH];
    WCHAR dir[MAX_PATH];

    /* ---- Locate ourselves ---- */
    if (!GetModuleFileNameW(NULL, selfPath, MAX_PATH))
        return 1;

    wcscpy_s(dir, MAX_PATH, selfPath);
    WCHAR *sep = wcsrchr(dir, L'\\');
    if (!sep) return 1;
    *sep = L'\0';

    /* ---- Decide launch path ---- */
    WCHAR launchDir[MAX_PATH];
    WCHAR launchExe[MAX_PATH];

    if (!PathHasNonAscii(dir))
    {
        /* Path is already ASCII-safe — launch directly. */
        wcscpy_s(launchDir, MAX_PATH, dir);
        wsprintfW(launchExe, L"%s\\rpm-encrypter.exe", dir);
    }
    else
    {
        /* ---- Copy to an ASCII-safe temp location ---- */
        WCHAR basePath[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", basePath, MAX_PATH);

        if (n == 0 || n >= MAX_PATH || PathHasNonAscii(basePath))
            wcscpy_s(basePath, MAX_PATH, L"C:\\ProgramData");

        WCHAR safeDir[MAX_PATH];
        WCHAR stampFile[MAX_PATH];
        wsprintfW(safeDir,   L"%s\\RPMEncrypter", basePath);
        wsprintfW(stampFile, L"%s\\.launcher_stamp", safeDir);

        /* Skip copy if stamp matches (app hasn't been updated). */
        if (!StampMatches(stampFile, selfPath))
        {
            /* Full copy needed — nuke old copy first. */
            NukeDir(safeDir);

            if (!CopyDirContents(dir, safeDir))
            {
                MessageBoxW(NULL,
                    L"RPM Encrypter kopyalanamad\x0131.\n\n"
                    L"Uygulamay\x0131 \x00F6zel karakter i\x00E7ermeyen bir\n"
                    L"klas\x00F6re ta\x015F\x0131y\x0131n.  \x00D6rnek: C:\\RPMEncrypter\n\n"
                    L"Could not copy the application to a safe path.\n"
                    L"Please move it to a folder without special characters.",
                    L"RPM Encrypter", MB_ICONERROR);
                return 1;
            }
            WriteStamp(stampFile, selfPath);
        }

        wcscpy_s(launchDir, MAX_PATH, safeDir);
        wsprintfW(launchExe, L"%s\\rpm-encrypter.exe", safeDir);
    }

    /* ---- Launch the real exe ---- */
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(launchExe, NULL, NULL, NULL, FALSE,
                        0, NULL, launchDir, &si, &pi))
    {
        WCHAR msg[512];
        wsprintfW(msg,
            L"rpm-encrypter.exe ba\x015Flat\x0131lamad\x0131.\nHata kodu: %lu",
            GetLastError());
        MessageBoxW(NULL, msg, L"RPM Encrypter", MB_ICONERROR);
        return 1;
    }

    /* Fire-and-forget: launcher exits, app runs independently. */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
