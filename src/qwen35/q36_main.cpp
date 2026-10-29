// src/qwen35/q36_main.cpp - strata-q36: the Qwen3.6 engine path on its own (the same entry point `strata` switches
// to for a qwen35moe model).
#include "strata/qwen35/engine.hpp"

#if defined(_WIN32)
// A silent fast-fail (exit code 0xC0000409, no log line, no event-log record) leaves nothing to work with.
// Print a stack to stderr on abort() (abort and uncaught C++ exceptions land here) and on the common fatal
// access violations, then let the process die as it would have. Names need the PDB next to the exe.
#include <windows.h>
#include <dbghelp.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>

namespace {

void q36_print_stack(const char* why) {
    static bool printing = false;
    if (printing) return;
    printing = true;
    std::fprintf(stderr, "strata-q36: %s, the stack (module + offset, names need strata.pdb next to the exe):\n", why);
    void* fr[32];
    const int n = CaptureStackBackTrace(0, 32, fr, nullptr);
    const HANDLE me = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    const bool sym = SymInitialize(me, nullptr, TRUE);
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR> (&q36_print_stack), &self);
    MODULEINFO mi{};
    const uintptr_t mbase = self && GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof mi)
                               ? reinterpret_cast<uintptr_t> (mi.lpBaseOfDll) : 0;
    const uintptr_t msize = mbase ? reinterpret_cast<uintptr_t> (mi.SizeOfImage) : 0;
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

void q36_on_abrt(int) {
    q36_print_stack("abort() was called");
    std::_Exit(134);
}

LONG WINAPI q36_on_se(EXCEPTION_POINTERS* ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    // the C++ exception code and the debugger breakpoints are not engine failures; every first-chance exception
    // passes here, so only the fatal ones print
    if (code == 0xC0000005 || code == 0xC00000FD || code == 0xC000001D || code == 0xC0000094 || code == 0xC0000417) {
        char why[80];
        std::snprintf(why, sizeof why, "an unhandled exception, code 0x%08lX", (unsigned long) code);
        q36_print_stack(why);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

struct q36_install {
    q36_install() {
        std::signal(SIGABRT, q36_on_abrt);
        AddVectoredExceptionHandler(0, q36_on_se);
    }
};
const q36_install q36_install_once;

}  // namespace
#endif

int main(int argc, char** argv) { return strata::qwen35::run(argc, argv); }
