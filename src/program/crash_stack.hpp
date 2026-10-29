// src/program/crash_stack.hpp - print a stack to stderr when the engine dies to abort() or a fatal exception.
// A silent fast-fail (exit code 0xC0000409, no log line, no event-log record) leaves nothing to work with:
// abort() and uncaught C++ exceptions land in the SIGABRT handler, access violations and friends in the
// vectored handler. Names need the PDB next to the exe. Windows only; other platforms die as they did.
#pragma once

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>

namespace strata {

inline void print_crash_stack(const char* why) {
    static bool printing = false;
    if (printing) return;
    printing = true;
    std::fprintf(stderr, "strata: %s, the stack (module + offset, names need strata.pdb next to the exe):\n", why);
    void* fr[32];
    const int n = CaptureStackBackTrace(0, 32, fr, nullptr);
    const HANDLE me = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    const bool sym = SymInitialize(me, nullptr, TRUE);
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR> (&print_crash_stack), &self);
    MODULEINFO mi{};
    const uintptr_t mbase = self && GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof mi)
                               ? reinterpret_cast<uintptr_t> (mi.lpBaseOfDll) : 0;
    const uintptr_t msize = mbase ? static_cast<uintptr_t> (mi.SizeOfImage) : 0;
    for (int i = 0; i < n; ++i) {
        const uintptr_t a = reinterpret_cast<uintptr_t> (fr[i]);
        if (mbase && a >= mbase && a < mbase + msize)
            std::fprintf(stderr, "  strata.exe+0x%llx", (unsigned long long) (a - mbase));
        else
            std::fprintf(stderr, "  %p", fr[i]);
        if (sym) {
            alignas(SYMBOL_INFO) char buf[sizeof(SYMBOL_INFO) + 256];
            SYMBOL_INFO* s = reinterpret_cast<SYMBOL_INFO*> (buf);
            s->SizeOfStruct = sizeof(SYMBOL_INFO);
            s->MaxNameLen = 255;
            DWORD64 disp = 0;
            if (SymFromAddr(me, a, &disp, s)) std::fprintf(stderr, "  %s+0x%llx", s->Name, (unsigned long long) disp);
            IMAGEHLP_LINE64 line{};
            line.SizeOfStruct = sizeof(line);
            DWORD ldisp = 0;
            if (SymGetLineFromAddr64(me, a, &ldisp, &line))
                std::fprintf(stderr, "  (%s:%lu)", line.FileName, (unsigned long) line.LineNumber);
        }
        std::fprintf(stderr, "\n");
    }
    std::fflush(stderr);
}

inline void on_sigabrt(int) {
    print_crash_stack("abort() was called");
    std::_Exit(134);
}

inline LONG WINAPI on_fatal_se(EXCEPTION_POINTERS* ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    // the C++ exception code and the debugger breakpoints are not engine failures; every first-chance exception
    // passes here, so only the fatal ones print
    if (code == 0xC0000005 || code == 0xC00000FD || code == 0xC000001D || code == 0xC0000094 || code == 0xC0000417) {
        char why[80];
        std::snprintf(why, sizeof why, "an unhandled exception, code 0x%08lX", (unsigned long) code);
        print_crash_stack(why);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

struct CrashStackInstall {
    CrashStackInstall() {
        std::signal(SIGABRT, on_sigabrt);
        AddVectoredExceptionHandler(0, on_fatal_se);
    }
};

}  // namespace strata

// put this once, at the top of main(): the handlers install before any engine code runs
#define STRATA_INSTALL_CRASH_STACK()                  \
    do {                                              \
        static const strata::CrashStackInstall once;  \
        (void) once;                                  \
    } while (0)
#else
#define STRATA_INSTALL_CRASH_STACK() do { } while (0)
#endif
