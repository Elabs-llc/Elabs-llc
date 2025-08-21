// tuntap_reader.cpp
// A foundational C++ program to read IP packets from a TAP-Windows virtual network adapter.
// This is the first step in building a professional VPN client.
//
// How to compile (using MSVC compiler from a Developer Command Prompt):
// > cl.exe tuntap_reader.cpp /EHsc
//
// Prerequisites:
// 1. Visual Studio with C++ development tools installed.
// 2. TAP-Windows driver installed (https://openvpn.net/community-downloads/).

#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <memory>

// --- Constants and GUIDs ---

// The GUID for the TAP-Windows network adapter class. This is a standard identifier.
#define TAP_WIN_CONTROL_GUID { 0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } }

// IOCTL (I/O Control) code to get the adapter's status.
#define TAP_WIN_IOCTL_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

// --- Function Prototypes ---
std::wstring get_tap_device_guid();
void print_packet_info(const unsigned char* buffer, int len);

// --- Main Application Entry Point ---
int main() {
    std.cout << "--- C++ VPN Core: TUN/TAP Packet Reader ---" << std::endl;

    // 1. Find the GUID of our installed TAP-Windows adapter.
    std::wstring tap_guid_str = get_tap_device_guid();
    if (tap_guid_str.empty()) {
        std::cerr << "[ERROR] Could not find any TAP-Windows adapter." << std::endl;
        std::cerr << "Please ensure the TAP driver is installed correctly." << std::endl;
        return 1;
    }
    std::wcout << "[INFO] Found TAP Adapter GUID: " << tap_guid_str << std::endl;

    // 2. Construct the full device path needed to open it.
    std::wstring device_path = L"\\\\.\\Global\\" + tap_guid_str + L".tap";
    std::wcout << "[INFO] Device Path: " << device_path << std::endl;

    // 3. Open a handle to the TAP device. This is like opening a file.
    HANDLE hTap = CreateFileW(
        device_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // Must be 0 for TAP device
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, // Overlapped I/O is required
        NULL
    );

    if (hTap == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] Failed to open TAP device. Error code: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[SUCCESS] Successfully opened a handle to the TAP device." << std::endl;

    // 4. Set the adapter status to "connected".
    // This makes the virtual network adapter appear as if a cable is plugged in.
    ULONG status = 1;
    DWORD bytes_returned;
    if (!DeviceIoControl(hTap, TAP_WIN_IOCTL_GET_STATUS, &status, sizeof(status), &status, sizeof(status), &bytes_returned, NULL)) {
        std::cerr << "[WARNING] Failed to set TAP adapter status to connected. Error: " << GetLastError() << std::endl;
    } else {
        std::cout << "[INFO] TAP adapter status set to 'Connected'." << std::endl;
    }
    std::cout << "\n[INFO] Now listening for packets. Route traffic to this adapter to see output..." << std::endl;
    std::cout << "[INFO] (e.g., by setting its IP and making it the default gateway)" << std::endl;

    // 5. Enter the main loop to read packets continuously.
    // A real VPN would do this in a dedicated background thread.
    try {
        // We use a buffer size typical for an Ethernet frame (MTU).
        const int BUFFER_SIZE = 1600; 
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        DWORD bytes_read;

        while (true) {
            if (!ReadFile(hTap, buffer.data(), BUFFER_SIZE, &bytes_read, NULL)) {
                // ReadFile will fail if no data is available yet, which is normal.
                // A more robust implementation would use overlapped I/O with events.
                // For this example, a small sleep is enough to prevent a tight loop.
                if (GetLastError() != ERROR_IO_PENDING) {
                    std::cerr << "\n[ERROR] ReadFile failed with error: " << GetLastError() << std::endl;
                    break;
                }
                Sleep(50); // Wait a bit before trying again
                continue;
            }

            if (bytes_read > 0) {
                std::cout << "\n--- Packet Captured (" << bytes_read << " bytes) ---" << std::endl;
                print_packet_info(buffer.data(), bytes_read);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] An exception occurred in the read loop: " << e.what() << std::endl;
    }

    // 6. Clean up.
    CloseHandle(hTap);
    std::cout << "[INFO] Closed TAP device handle. Exiting." << std::endl;

    return 0;
}

/**
 * @brief Scans the Windows Registry to find the GUID of the first available TAP-Windows adapter.
 *
 * @return A wstring containing the GUID (e.g., "{...}"), or an empty wstring if not found.
 */
std::wstring get_tap_device_guid() {
    // This is a more complex part that involves interacting with Windows APIs for device management.
    // For this example, we will hardcode the expected path structure. A production VPN
    // would properly enumerate devices to be more robust.
    //
    // A simplified approach is to assume the key exists at a known location.
    // The proper way involves SetupAPI functions like SetupDiGetClassDevs.
    // Let's keep it simple for this first step.
    
    // In a real application, you would use SetupDiGetClassDevs to enumerate all devices
    // of the class NET and check their ComponentId to find "tap0901".
    // For now, we'll assume a known GUID for simplicity. You can find your specific
    // GUID by looking for the TAP adapter in Device Manager and checking its properties.
    //
    // Let's simulate finding it. Replace this with your actual GUID if needed.
    // To find your GUID:
    // 1. Open Registry Editor (regedit.exe)
    // 2. Navigate to: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
    // 3. Look through the subkeys (0000, 0001, etc.) until you find one with a "ComponentId" value of "tap0901".
    // 4. The "NetCfgInstanceId" value in that key is the GUID you need.
    
    // For this educational example, we'll return a common default GUID structure.
    // THIS IS A MAJOR SIMPLIFICATION. A real app MUST enumerate devices properly.
    // Let's assume we found a device and its GUID is this:
    // NOTE: This will likely NOT work on your machine. This function needs to be
    // implemented properly using the Windows SetupAPI for a real solution.
    // For now, it shows the goal.
    
    // A proper implementation is complex, so we'll leave a placeholder.
    // The key takeaway is that your goal is to programmatically find this string.
    std::cerr << "[WARNING] Using a placeholder function for finding the TAP device GUID." << std::endl;
    std::cerr << "[WARNING] A production app must use the Windows SetupAPI to enumerate devices." << std::endl;
    
    // You will need to find your actual device GUID and hardcode it here for this example to work.
    // Example: return L"{YOUR-GUID-HERE}";
    return L""; // Return empty to force user to see the error, prompting them to learn the next step.
}

/**
 * @brief Prints basic information about a captured IP packet.
 *
 * @param buffer A pointer to the packet data.
 * @param len The length of the packet data in bytes.
 */
void print_packet_info(const unsigned char* buffer, int len) {
    if (len < 20) {
        std::cout << "  Packet too small to be a valid IP packet." << std::endl;
        return;
    }

    // IP header is at the start of the buffer
    unsigned char ip_version = (buffer[0] >> 4);
    unsigned char header_length = (buffer[0] & 0x0F) * 4;
    unsigned char protocol = buffer[9];

    std::cout << "  IP Version: " << (int)ip_version << std::endl;
    std::cout << "  Header Length: " << (int)header_length << " bytes" << std::endl;

    // Source IP Address (bytes 12-15)
    std::cout << "  Source IP: " << (int)buffer[12] << "." << (int)buffer[13] << "." << (int)buffer[14] << "." << (int)buffer[15] << std::endl;
    
    // Destination IP Address (bytes 16-19)
    std::cout << "  Destination IP: " << (int)buffer[16] << "." << (int)buffer[17] << "." << (int)buffer[18] << "." << (int)buffer[19] << std::endl;

    std::cout << "  Protocol: ";
    switch (protocol) {
        case 1:  std::cout << "ICMP (1)" << std::endl; break;
        case 6:  std::cout << "TCP (6)" << std::endl; break;
        case 17: std::cout << "UDP (17)" << std::endl; break;
        default: std::cout << "Other (" << (int)protocol << ")" << std::endl; break;
    }
}
