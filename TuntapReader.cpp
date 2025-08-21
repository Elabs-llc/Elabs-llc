// tuntap_reader.cpp
// The C++ client that captures packets, ENCRYPTS them, and sends them to the server.
//
// How to compile (using MSVC compiler from a Developer Command Prompt):
// Assumes OpenSSL is installed in C:\OpenSSL-Win64
// > cl.exe tuntap_reader.cpp /EHsc /I"C:\OpenSSL-Win64\include" /link setupapi.lib ws2_32.lib "C:\OpenSSL-Win64\lib\libssl.lib" "C:\OpenSSL-Win64\lib\libcrypto.lib"
//
// Prerequisites:
// 1. Visual Studio with C++ development tools.
// 2. TAP-Windows driver installed.
// 3. OpenSSL for Windows installed.

#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <thread>
#include <SetupAPI.h>
#include <devguid.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>

// Link against required libraries
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


// --- Configuration ---
const char* SERVER_IP = "127.0.0.1"; // IMPORTANT: Change to your server's public IP
const int SERVER_PORT = 8888;

// --- Encryption Configuration ---
// IMPORTANT: This key and IV must be IDENTICAL on both the client and server.
const unsigned char aes_key[32] = "01234567890123456789012345678901"; // 256-bit key
const unsigned char aes_iv[16] = "0123456789012345"; // 128-bit IV

// --- Constants and GUIDs ---
const GUID NET_CLASS_GUID = { 0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_COMPONENT_ID L"tap0901"

// --- Function Prototypes ---
std::wstring get_tap_device_guid();
void server_listener(SOCKET serverSocket, HANDLE hTap);
int encrypt_packet(const std::vector<unsigned char>& plaintext_data, std::vector<unsigned char>& encrypted_data);
int decrypt_packet(const std::vector<unsigned char>& encrypted_data, std::vector<unsigned char>& decrypted_data);

// --- Main Application Entry Point ---
int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "--- C++ VPN Client Core (with Encryption) ---" << std::endl;

    // 1. Find the GUID of our installed TAP-Windows adapter.
    std::wstring tap_guid_str = get_tap_device_guid();
    if (tap_guid_str.empty()) {
        std::cerr << "[ERROR] Could not find any TAP-Windows adapter." << std::endl;
        system("pause");
        return 1;
    }
    std::wcout << "[INFO] Found TAP Adapter GUID: " << tap_guid_str << std::endl;

    // 2. Construct the full device path.
    std::wstring device_path = L"\\\\.\\Global\\" + tap_guid_str + L".tap";
    std::wcout << "[INFO] Device Path: " << device_path << std::endl;

    // 3. Open a handle to the TAP device.
    HANDLE hTap = CreateFileW(device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
    if (hTap == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] Failed to open TAP device. Error code: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "[SUCCESS] Successfully opened a handle to the TAP device." << std::endl;

    // 4. Set the adapter status to "connected".
    ULONG status = 1;
    DWORD bytes_returned;
    DeviceIoControl(hTap, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &bytes_returned, NULL);
    std::cout << "[INFO] TAP adapter status set to 'Connected'." << std::endl;

    // 5. Initialize Winsock and connect to the VPN server
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    std::cout << "[INFO] Connecting to server " << SERVER_IP << ":" << SERVER_PORT << "..." << std::endl;
    if (connect(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Failed to connect to server." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        system("pause");
        return 1;
    }
    std::cout << "[SUCCESS] Connected to VPN server." << std::endl;

    // 6. Start a listener thread to receive data from the server
    std::thread listener(server_listener, serverSocket, hTap);
    listener.detach();

    // 7. Enter the main loop to read packets from TAP, encrypt, and send to server.
    std::cout << "\n[INFO] Now capturing, encrypting, and sending packets..." << std::endl;
    try {
        const int BUFFER_SIZE = 2048;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        DWORD bytes_read;
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        while (true) {
            if (!ReadFile(hTap, buffer.data(), BUFFER_SIZE, &bytes_read, &overlapped)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    std::cerr << "\n[ERROR] ReadFile from TAP failed with error: " << GetLastError() << std::endl;
                    break;
                }
                WaitForSingleObject(overlapped.hEvent, INFINITE);
                GetOverlappedResult(hTap, &overlapped, &bytes_read, FALSE);
            }

            if (bytes_read > 0) {
                std::vector<unsigned char> plaintext_packet(buffer.begin(), buffer.begin() + bytes_read);
                std::vector<unsigned char> encrypted_packet;

                // Encrypt the captured packet
                if (encrypt_packet(plaintext_packet, encrypted_packet) > 0) {
                    // Send the encrypted packet to the server
                    if (send(serverSocket, (const char*)encrypted_packet.data(), encrypted_packet.size(), 0) == SOCKET_ERROR) {
                        std::cerr << "[ERROR] send to server failed." << std::endl;
                        break;
                    }
                } else {
                    std::cerr << "[ERROR] Encryption failed for an outgoing packet." << std::endl;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] An exception occurred in the main loop: " << e.what() << std::endl;
    }

    // 8. Clean up.
    closesocket(serverSocket);
    WSACleanup();
    CloseHandle(hTap);
    EVP_cleanup();
    ERR_free_strings();
    std::cout << "[INFO] Disconnected and cleaned up resources. Exiting." << std::endl;

    return 0;
}

/**
 * @brief Listens for encrypted data from the server, decrypts it, and writes it to the TAP adapter.
 */
void server_listener(SOCKET serverSocket, HANDLE hTap) {
    const int BUFFER_SIZE = 4096;
    std::vector<unsigned char> encrypted_buffer(BUFFER_SIZE);
    
    while (true) {
        int bytes_received = recv(serverSocket, (char*)encrypted_buffer.data(), BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            std::vector<unsigned char> received_data(encrypted_buffer.begin(), encrypted_buffer.begin() + bytes_received);
            std::vector<unsigned char> decrypted_packet;

            // Decrypt the packet from the server
            if (decrypt_packet(received_data, decrypted_packet) > 0) {
                DWORD bytes_written;
                if (!WriteFile(hTap, decrypted_packet.data(), decrypted_packet.size(), &bytes_written, NULL)) {
                     std::cerr << "[ERROR] WriteFile to TAP failed: " << GetLastError() << std::endl;
                }
            } else {
                std::cerr << "[ERROR] Decryption failed for an incoming packet." << std::endl;
            }
        } else if (bytes_received == 0) {
            std::cout << "[INFO] Server closed the connection." << std::endl;
            break;
        } else {
            std::cerr << "[ERROR] recv from server failed." << std::endl;
            break;
        }
    }
}

/**
 * @brief Encrypts data using AES-256-CBC.
 */
int encrypt_packet(const std::vector<unsigned char>& plaintext_data, std::vector<unsigned char>& encrypted_data) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    encrypted_data.resize(plaintext_data.size() + 16);
    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) return 0;
    if(1 != EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, plaintext_data.data(), plaintext_data.size())) return 0;
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len)) return 0;
    ciphertext_len += len;
    encrypted_data.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/**
 * @brief Decrypts data using AES-256-CBC.
 */
int decrypt_packet(const std::vector<unsigned char>& encrypted_data, std::vector<unsigned char>& decrypted_data) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    decrypted_data.resize(encrypted_data.size());
    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) return 0;
    if(1 != EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(), encrypted_data.size())) return 0;
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len)) return 0;
    plaintext_len += len;
    decrypted_data.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


/**
 * @brief Scans the system for a TAP-Windows adapter and returns its GUID.
 */
std::wstring get_tap_device_guid() {
    HDEVINFO devInfo;
    SP_DEVINFO_DATA devInfoData;
    devInfo = SetupDiGetClassDevs(&NET_CLASS_GUID, NULL, NULL, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return L"";
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devInfo, i, &devInfoData); ++i) {
        wchar_t componentId[256];
        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devInfoData, SPDRP_COMPATIBLEIDS, NULL, (PBYTE)componentId, sizeof(componentId), NULL)) {
            if (wcscmp(componentId, TAP_COMPONENT_ID) == 0) {
                wchar_t netCfgInstanceId[256];
                if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devInfoData, SPDRP_NETCFGINSTANCEID, NULL, (PBYTE)netCfgInstanceId, sizeof(netCfgInstanceId), NULL)) {
                    SetupDiDestroyDeviceInfoList(devInfo);
                    return std::wstring(netCfgInstanceId);
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    return L"";
}
