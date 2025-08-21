// vpn_killswitch.cpp
// A module to implement a VPN kill switch using the Windows Filtering Platform (WFP).
// This logic should be integrated into your main C++ Windows Service.
//
// How to compile (using MSVC compiler from a Developer Command Prompt):
// > cl.exe vpn_killswitch.cpp /EHsc Fwpuclnt.lib Rpcrt4.lib
//
// Prerequisites:
// 1. Visual Studio with C++ development tools.
// 2. Must be run with Administrator privileges.

#include <windows.h>
#include <fwpmu.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib") // For UUID functions

// --- Global Handles & GUIDs ---
HANDLE g_engineHandle = NULL;
UINT64 g_blockAllFilterId = 0;
UINT64 g_permitVpnFilterId = 0;

// GUID for our custom WFP provider. This identifies our application's rules.
// Generate a new GUID for your own project using `uuidgen` in a developer prompt.
const GUID PROVIDER_KEY = { 0x8a8... }; // Replace with your own GUID
const GUID SUBLAYER_KEY = { 0x9a9... }; // Replace with your own GUID

// --- Function Prototypes ---
bool InitializeWfp();
void CleanupWfp();
bool AddBlockAllRule();
bool AddPermitVpnRule(const std::wstring& vpnServerIp);
void RemovePermitVpnRule();
void RemoveBlockAllRule();

// --- Main Function (for demonstration) ---
int main() {
    std::wcout << L"--- VPN Kill Switch Test ---" << std::endl;

    if (!InitializeWfp()) {
        std::cerr << "Failed to initialize WFP engine." << std::endl;
        return 1;
    }

    std::wcout << L"Press Enter to add the 'Block All' rule..." << std::endl;
    std::wcin.get();

    if (AddBlockAllRule()) {
        std::wcout << L"[SUCCESS] 'Block All' rule added. Your internet should now be blocked." << std::endl;
    } else {
        std::wcerr << L"[ERROR] Failed to add 'Block All' rule." << std::endl;
    }

    std::wcout << L"\nPress Enter to add the 'Permit VPN' rule (e.g., for server 8.8.8.8)..." << std::endl;
    std::wcin.get();

    // In your real app, get this IP from your config file
    if (AddPermitVpnRule(L"8.8.8.8")) {
        std::wcout << L"[SUCCESS] 'Permit VPN' rule added. You should only be able to reach the VPN server." << std::endl;
    } else {
        std::wcerr << L"[ERROR] Failed to add 'Permit VPN' rule." << std::endl;
    }

    std::wcout << L"\nPress Enter to remove the 'Permit VPN' rule..." << std::endl;
    std::wcin.get();
    RemovePermitVpnRule();
    std::wcout << L"[INFO] 'Permit VPN' rule removed. Internet should be blocked again." << std::endl;

    std::wcout << L"\nPress Enter to remove all rules and clean up..." << std::endl;
    std::wcin.get();
    
    CleanupWfp();
    std::wcout << L"[INFO] All rules removed and WFP engine closed." << std::endl;

    return 0;
}

// --- WFP Implementation ---

bool InitializeWfp() {
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_engineHandle);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Add a sublayer for our rules to ensure they are processed in the right order
    FWPM_SUBLAYER0 subLayer = {0};
    subLayer.subLayerKey = SUBLAYER_KEY;
    subLayer.displayData.name = (wchar_t*)L"MyVPN Kill Switch Sub-Layer";
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT; // Rule persists across reboots
    subLayer.weight = 0xFFFF; // Highest weight to ensure it's evaluated first

    result = FwpmSubLayerAdd0(g_engineHandle, &subLayer, NULL);
    // ERROR_ALREADY_EXISTS is okay, means it's already set up
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS) {
        FwpmEngineClose0(g_engineHandle);
        return false;
    }
    return true;
}

void CleanupWfp() {
    if (g_engineHandle) {
        RemoveBlockAllRule(); // Ensure the block rule is removed on cleanup
        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
    }
}

bool AddBlockAllRule() {
    if (!g_engineHandle) return false;

    FWPM_FILTER0 filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.subLayerKey = SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0; // Lower weight, so permit rules can override it
    filter.displayData.name = (wchar_t*)L"MyVPN Kill Switch - Block All";
    
    DWORD result = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_blockAllFilterId);
    return (result == ERROR_SUCCESS);
}

bool AddPermitVpnRule(const std::wstring& vpnServerIp) {
    if (!g_engineHandle) return false;

    FWPM_FILTER0 filter = {0};
    FWPM_FILTER_CONDITION0 condition = {0};

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.subLayerKey = SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x1; // Higher weight to override the block rule
    filter.displayData.name = (wchar_t*)L"MyVPN Kill Switch - Permit VPN Traffic";
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    // Condition: If remote IP address matches the VPN server's IP
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_V4_ADDR_MASK;

    // Convert string IP to a UINT32
    UINT32 ipAddr = 0;
    InetPtonW(AF_INET, vpnServerIp.c_str(), &ipAddr);
    condition.conditionValue.v4AddrMask = &ipAddr;

    DWORD result = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_permitVpnFilterId);
    return (result == ERROR_SUCCESS);
}

void RemovePermitVpnRule() {
    if (g_engineHandle && g_permitVpnFilterId != 0) {
        FwpmFilterDeleteById0(g_engineHandle, g_permitVpnFilterId);
        g_permitVpnFilterId = 0;
    }
}

void RemoveBlockAllRule() {
    if (g_engineHandle && g_blockAllFilterId != 0) {
        FwpmFilterDeleteById0(g_engineHandle, g_blockAllFilterId);
        g_blockAllFilterId = 0;
    }
}
