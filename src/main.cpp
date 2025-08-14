#include <cstdlib>
#include <cstring>
#include <lyra/lyra.hpp>
#include <windows.h>

#include <filesystem>
#include <set>
#include <thread>

#include <tlhelp32.h>

struct Options {
    std::string module;
    std::string target;
    std::string launch;
    int delay { 0 };
    int close { 5 };
};

wchar_t* char_to_wchar(const char* c)
{
    const size_t size = strlen(c) + 1;
    const auto wc = new wchar_t[size];
    mbstowcs(wc, c, size);
    return wc;
}

void wait_exit(const int code)
{
    std::this_thread::sleep_for(std::chrono::seconds(10));
    exit(code);
}

bool check_file_description(const char* buf, const char* module_path)
{
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    }* translate_query;

    char id[50];
    char* file_description;
    unsigned int query_size, file_desc_size;

    if (!VerQueryValueA(buf, "\\VarFileInfo\\Translation", (void**)&translate_query, &query_size)) {
        std::cerr << "ERROR: File information query failed" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    // Look for the 3DMigoto file description in all language blocks... We
    // could likely skip the loop since we know which language it should be
    // in. However, for some reason we included it in the German section, which
    // we might want to change, so this way we won't need to adjust this
    // code if we do:
    for (unsigned i = 0; i < (query_size / sizeof(struct LANGANDCODEPAGE)); i++) {
        const HRESULT hr = _snprintf_s(id, 50, 50, R"(\StringFileInfo\%04x%04x\FileDescription)",
            translate_query[i].wLanguage,
            translate_query[i].wCodePage);

        if (FAILED(hr)) {
            std::cerr << "ERROR: File description query bugged" << std::endl;
            wait_exit(EXIT_FAILURE);
        }

        if (!VerQueryValueA(buf, id, reinterpret_cast<void**>(&file_description), &file_desc_size)) {
            std::cerr << "ERROR: File description query failed" << std::endl;
            wait_exit(EXIT_FAILURE);
        }

        // Only look for the 3Dmigoto prefix. We've had a whitespace
        // error in the description for all this time that we want to
        // ignore, and we later might want to add other 3DMigoto DLLs
        // like d3d9 and d3d12 with injection support
        if (!strncmp(file_description, "3Dmigoto", 8)) {
            return true;
        }
    }

    return false;
}

void check_3dmigoto_version(const char* module_path)
{
    VS_FIXEDFILEINFO* query = nullptr;
    DWORD handle = 0;

    unsigned int size = GetFileVersionInfoSizeA(module_path, &handle);
    if (!size) {
        std::cerr << "ERROR: Failed to get file version info size" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    const auto buffer = new char[size];

    if (!GetFileVersionInfoA(module_path, handle, size, buffer)) {
        std::cerr << "ERROR: Failed to get file version info" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (!check_file_description(buffer, module_path)) {
        std::cerr << "ERROR: The requested module is not 3DMigoto" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (!VerQueryValueA(buffer, "\\", reinterpret_cast<void**>(&query), &size)) {
        std::cerr << "ERROR: Failed to query 3DMigoto version" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    const auto major = query->dwProductVersionMS >> 16;
    const auto minor = query->dwProductVersionMS & 0xffff;
    const auto patch = query->dwProductVersionLS >> 16;

    std::cout << "INFO: 3DMigoto version: " << major << "." << minor << "." << patch << std::endl;

    if (query->dwProductVersionMS < 0x00010003 || query->dwProductVersionMS == 0x00010003 && query->dwProductVersionLS < 0x000f0000) {
        std::cerr << "ERROR: This version of 3DMigoto is too old to be safely loaded - please use 1.3.15 or later" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    delete[] buffer;
}

void validate_options(const lyra::cli& cli, const int argc, char** argv, const Options& options)
{
    if (const auto result = cli.parse({ argc, argv }); !result) {
        std::cerr << "ERROR: " << result.message() << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (options.module.empty()) {
        std::cerr << "ERROR: You must specify a module" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (options.target.empty()) {
        std::cerr << "ERROR: You must specify a target" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (!std::filesystem::exists(options.module)) {
        std::cerr << "ERROR: Module does not exist" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (options.delay < 0) {
        std::cerr << "ERROR: Delay must be greater than or equal to 0" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    if (options.close < 0) {
        std::cerr << "ERROR: Close timer must be greater than or equal to 0" << std::endl;
        wait_exit(EXIT_FAILURE);
    }
}

void setup_hook(const HMODULE module, const LPCSTR func_name, const int hook_id, HHOOK& out_hook)
{
    const auto hook_func = GetProcAddress(module, func_name);
    if (hook_func == nullptr) {
        std::cerr << "ERROR: Failed to get hook function" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    const auto hook = SetWindowsHookEx(hook_id, reinterpret_cast<HOOKPROC>(hook_func), module, 0);
    if (hook == nullptr) {
        std::cerr << "ERROR: Failed to set hook" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    out_hook = hook;
    std::cout << "INFO: Hook set up" << std::endl;
}

void launch_process(const std::string& executable_path)
{
    const std::filesystem::path launch_path(executable_path);

    /*
     * Check if the launch path is valid (aka. if the file does exist)
     */
    if (std::filesystem::status(launch_path).type() != std::filesystem::file_type::regular) {
        std::cerr << "ERROR: Launch Path is invalid" << std::endl;
        exit(1);
    }

    const auto file = executable_path.c_str();

    /*
     * Little shitty hack to get the absolute parent path of the executable.
     * WinAPI makes this very annoying, fuck microsoft.
     */
    const auto directory_u8 = launch_path.parent_path().u8string();
    const auto directory = (std::string(directory_u8.begin(), directory_u8.end()) + "\\").c_str();

    if (CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) != S_OK) {
        std::cerr << "ERROR: CoInitializeEx failed to execute" << std::endl;
        exit(1);
    }

    /*
     * Start new process.
     */
    if (ShellExecuteA(nullptr, nullptr, file, nullptr, directory, SW_SHOWNORMAL) == nullptr) {
        std::cerr << "ERROR: ShellExecuteA failed to execute" << std::endl;
        exit(1);
    }
}

void load_module(const std::string& module_path, HMODULE& out_module)
{
    const auto module = LoadLibraryA(module_path.c_str());
    if (module == nullptr) {
        const auto error = GetLastError();
        std::cerr << "ERROR: Failed to load module " << module_path << ": " << error << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    out_module = module;
    std::cout << "INFO: Module loaded" << std::endl;
}

bool find_process(const std::string& process_name, PROCESSENTRY32& out_process)
{
    const wchar_t* target = char_to_wchar(process_name.c_str());

    // ReSharper disable once CppLocalVariableMayBeConst
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        const auto exe_file = char_to_wchar(process.szExeFile);
        const auto result = wcscmp(exe_file, target);
        delete[] exe_file;

        if (result == 0) {
            out_process = process;
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &process));

    return false;
}

void elevate_privileges(int argc, char** argv)
{
    DWORD size = sizeof(TOKEN_ELEVATION);
    TOKEN_ELEVATION Elevation;
    wchar_t path[MAX_PATH];
    HANDLE token = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return;

    if (!GetTokenInformation(token, TokenElevation, &Elevation, sizeof(Elevation), &size)) {
        CloseHandle(token);
        return;
    }

    CloseHandle(token);

    if (Elevation.TokenIsElevated)
        return;

    if (!GetModuleFileNameW(nullptr, path, MAX_PATH))
        return;

    std::string parameters;
    for (int i = 1; i < argc; i++) {
        if (auto arg = std::string(argv[i]); arg.find(' ') != std::string::npos) {
            parameters += "\"" + arg + "\"" + " ";
        } else {
            parameters += arg + " ";
        }
    }

    const auto charPar = char_to_wchar(parameters.c_str());

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    int rc = static_cast<int>(reinterpret_cast<uintptr_t>(ShellExecuteW(nullptr, L"runas", path, charPar, nullptr, SW_SHOWNORMAL)));
    if (rc > 32) {
        delete[] charPar;
        exit(0);
    }

    delete[] charPar;

    if (rc == SE_ERR_ACCESSDENIED) {
        std::cerr << "ERROR: Access Denied" << std::endl;
        wait_exit(EXIT_FAILURE);
    }

    std::cerr << "ERROR: Unable to run as admin: " << rc << std::endl;
    wait_exit(EXIT_FAILURE);
}

int main(const int argc, char** argv)
{
    Options options;

    const auto cli = lyra::cli()
        | lyra::opt(options.module, "module")
            ["-m"]["--module"]("Which module to inject into a process?")
        | lyra::opt(options.target, "target")
            ["-t"]["--target"]("Which process to target?")
        | lyra::opt(options.launch, "launch")
            ["-l"]["--launch"]("Which process to launch?")
        | lyra::opt(options.delay, "delay")
            ["-d"]["--delay"]("How long to wait before checking injection?")
        | lyra::opt(options.close, "close")
            ["-c"]["--close"]("How long to wait before closing?");

    validate_options(cli, argc, argv, options);
    check_3dmigoto_version(options.module.c_str());

    elevate_privileges(argc, argv);

    HMODULE module;
    load_module(options.module, module);

    HHOOK hook;
    setup_hook(module, "CBTProc", WH_CBT, hook);

    /*
     * Allow the user to launch a new process (most likely the target)
     */
    if (!options.launch.empty()) {
        launch_process(options.launch);
        std::cout << "INFO: Process launched" << std::endl;
    }

    /*
     * Allow the user to add a delay before checking if the target is open.
     */
    // ReSharper disable once CppDFAConstantConditions
    // ReSharper disable once CppDFAUnreachableCode
    if (options.delay > 0) {
        std::cout << "INFO: Delaying for " << options.delay << " milliseconds.." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(options.delay));
    }

    std::cout << "INFO: Waiting for target.." << std::endl;

    for (int seconds = 0; true; seconds++) {
        PROCESSENTRY32 process;

        if (!find_process(options.target, process)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        std::cout << "INFO: Target process found (" << options.target << ") with PID " << process.th32ProcessID << std::endl;
        break;
    }

    std::cout << "INFO: Closing in " << options.close << " seconds.." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(options.close));

    UnhookWindowsHookEx(hook);
    FreeLibrary(module);
    return EXIT_SUCCESS;
}
