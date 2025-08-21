// vpn_service.cpp
// The C++ VPN client restructured as a background Windows Service.
// It reads credentials from a config file and logs its activity to a text file.
//
// How to compile (using MSVC compiler from a Developer Command Prompt):
// Assumes OpenSSL is installed in C:\OpenSSL-Win64
// > cl.exe vpn_service.cpp /EHsc /I"C:\OpenSSL-Win64\include" /link setupapi.lib ws2_32.lib advapi32.lib "C:\OpenSSL-Win64\lib\libssl.lib" "C:\OpenSSL-Win64\lib\libcrypto.lib"

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <SetupAPI.h>
#include <devguid.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib") // For service functions
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// --- Service Globals ---
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::ofstream         g_logFile;

// --- VPN Core Globals ---
bool g_vpnActive = false;
std::thread g_vpnThread;

// --- Function Prototypes ---
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode);
void VpnMainThread(std::string username, std::string password);
void Log(const std::string& message);

// --- Main Application Entry Point ---
int main(int argc, char *argv[]) {
    // This is the entry point when the service is started by the SCM
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {(LPSTR)"MyVPNService", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        // This will happen if you try to run the .exe directly
        std::cerr << "Error: This program can only be run as a Windows Service." << std::endl;
        return GetLastError();
    }

    return 0;
}

// --- Service Functions ---

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler("MyVPNService", ServiceCtrlHandler);
    if (g_StatusHandle == NULL) return;

    // Open log file
    g_logFile.open("C:\\vpn_log.txt", std::ios_base::app); // Log to a fixed location
    Log("--- ServiceMain started ---");

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    // Report the service is starting
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // --- Read Config ---
    char username[128] = {0};
    char password[128] = {0};
    GetPrivateProfileString("Credentials", "Username", "", username, sizeof(username), ".\\config.ini");
    GetPrivateProfileString("Credentials", "Password", "", password, sizeof(password), ".\\config.ini");
    Log("Read credentials from config.ini");

    // Start the actual VPN logic in a separate thread
    g_vpnActive = true;
    g_vpnThread = std::thread(VpnMainThread, std::string(username), std::string(password));

    // Report the service is running
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    Log("Service is now running.");

    // Wait until the service is stopped
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    // Cleanup
    Log("--- ServiceMain stopping ---");
    g_vpnActive = false;
    if (g_vpnThread.joinable()) {
        g_vpnThread.join();
    }
    
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    g_logFile.close();
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;
        
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        // Signal the main thread to stop
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

// --- VPN Core Logic ---

void VpnMainThread(std::string username, std::string password) {
    Log("VpnMainThread started.");
    // This function now contains ALL the logic from the previous client's main()
    // e.g., finding the TAP device, connecting to the server, TLS auth, packet loops, etc.
    // For brevity, we'll simulate the connection loop.

    // --- Placeholder for full VPN client logic ---
    Log("Simulating connection to server with user: " + username);
    // 1. Find TAP adapter...
    // 2. Connect TCP socket to server...
    // 3. Perform TLS handshake and authentication...
    // 4. If successful, enter packet read/write loops...
    
    while (g_vpnActive) {
        // This is the main loop where you would read from the TAP adapter
        // and the server socket.
        Log("VPN loop is active...");
        Sleep(10000); // Simulate work
    }

    Log("VpnMainThread is shutting down.");
}

void Log(const std::string& message) {
    if (g_logFile.is_open()) {
        g_logFile << message << std::endl;
    }
}
