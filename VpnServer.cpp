// vpn_server.cpp
// A foundational C++ program for the server-side of our VPN.
// It listens for a client, receives ENCRYPTED raw IP packets, decrypts them,
// and forwards them using a raw socket.
//
// How to compile (on Linux with g++):
// > g++ vpn_server.cpp -o vpn_server -lpthread -lssl -lcrypto
//
// How to run (on Linux):
// > sudo ./vpn_server 
// (Root permissions are required to create raw sockets)

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> // For IP header structure
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <thread>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close

// --- Encryption Configuration ---
// IMPORTANT: This key and IV must be IDENTICAL on both the client and server.
// In a real product, this would be negotiated securely, not hardcoded.
const unsigned char aes_key[32] = "01234567890123456789012345678901"; // 256-bit key
const unsigned char aes_iv[16] = "0123456789012345"; // 128-bit IV

// --- Function Prototypes ---
void print_packet_info(const unsigned char* buffer, int len);
void handle_client(SOCKET clientSocket);
int decrypt_packet(const std::vector<unsigned char>& encrypted_data, std::vector<unsigned char>& decrypted_data);
int encrypt_packet(const std::vector<unsigned char>& decrypted_data, std::vector<unsigned char>& encrypted_data);

// --- Main Application Entry Point ---
int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "--- C++ VPN Server (with Encryption) ---" << std::endl;

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed." << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8888);

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed." << std::endl;
        closesocket(listenSocket);
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Listen failed." << std::endl;
        closesocket(listenSocket);
        return 1;
    }

    std::cout << "[INFO] Server listening on port 8888..." << std::endl;

    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "[WARNING] Accept failed." << std::endl;
            continue;
        }
        
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        getpeername(clientSocket, (struct sockaddr*)&client_addr, &client_len);
        std::cout << "[INFO] Client connected from " << inet_ntoa(client_addr.sin_addr) << ". Starting handler thread..." << std::endl;
        
        std::thread clientThread(handle_client, clientSocket);
        clientThread.detach();
    }

    closesocket(listenSocket);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

/**
 * @brief Handles the communication with a single connected client.
 */
void handle_client(SOCKET clientSocket) {
    const int BUFFER_SIZE = 4096; // Increased buffer for encrypted data
    std::vector<unsigned char> encrypted_buffer(BUFFER_SIZE);
    std::vector<unsigned char> decrypted_buffer;

    while (true) {
        int bytes_received = recv(clientSocket, (char*)encrypted_buffer.data(), BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            std::vector<unsigned char> received_data(encrypted_buffer.begin(), encrypted_buffer.begin() + bytes_received);
            
            // Decrypt the received packet
            if (decrypt_packet(received_data, decrypted_buffer) <= 0) {
                std::cerr << "[ERROR] Decryption failed." << std::endl;
                continue;
            }

            std::cout << "\n--- Decrypted Packet from Client (" << decrypted_buffer.size() << " bytes) ---" << std::endl;
            print_packet_info(decrypted_buffer.data(), decrypted_buffer.size());

            // --- REAL FORWARDING LOGIC ---
            SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (rawSocket == INVALID_SOCKET) {
                perror("[ERROR] Failed to create raw socket. Are you root?");
                continue;
            }

            struct iphdr* ip_header = (struct iphdr*)decrypted_buffer.data();
            sockaddr_in destAddr;
            destAddr.sin_family = AF_INET;
            destAddr.sin_addr.s_addr = ip_header->daddr;

            if (sendto(rawSocket, decrypted_buffer.data(), decrypted_buffer.size(), 0, (struct sockaddr*)&destAddr, sizeof(destAddr)) < 0) {
                perror("[ERROR] sendto failed on raw socket");
                closesocket(rawSocket);
                continue;
            }
            std::cout << "  [FORWARD] Packet sent to destination." << std::endl;
            
            std::vector<unsigned char> recv_buffer_raw(BUFFER_SIZE);
            int response_bytes = recvfrom(rawSocket, (char*)recv_buffer_raw.data(), BUFFER_SIZE, 0, NULL, NULL);

            if (response_bytes > 0) {
                 std::cout << "  [RESPONSE] Received " << response_bytes << " bytes from destination." << std::endl;
                 std::vector<unsigned char> response_data(recv_buffer_raw.begin(), recv_buffer_raw.begin() + response_bytes);
                 std::vector<unsigned char> encrypted_response;
                 
                 // Encrypt the response before sending it back
                 if (encrypt_packet(response_data, encrypted_response) <= 0) {
                     std::cerr << "[ERROR] Encryption of response failed." << std::endl;
                 } else {
                     if (send(clientSocket, (char*)encrypted_response.data(), encrypted_response.size(), 0) < 0) {
                         perror("[ERROR] Failed to send encrypted response back to client");
                     }
                 }
            }
            
            closesocket(rawSocket);

        } else if (bytes_received == 0) {
            std::cout << "[INFO] Client disconnected." << std::endl;
            break;
        } else {
            perror("[ERROR] recv from client failed");
            break;
        }
    }

    closesocket(clientSocket);
}

/**
 * @brief Decrypts data using AES-256-CBC.
 * @return The size of the decrypted data, or 0 on failure.
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
 * @brief Encrypts data using AES-256-CBC.
 * @return The size of the encrypted data, or 0 on failure.
 */
int encrypt_packet(const std::vector<unsigned char>& plaintext_data, std::vector<unsigned char>& encrypted_data) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // The output buffer needs to be slightly larger than the input for padding
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
 * @brief Prints basic information about a captured IP packet.
 */
void print_packet_info(const unsigned char* buffer, int len) {
    if (len < 20) {
        std::cout << "  Packet too small to be a valid IP packet." << std::endl;
        return;
    }
    struct iphdr* ip_header = (struct iphdr*)buffer;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    std::cout << "  IP Version: " << (int)ip_header->version << std::endl;
    std::cout << "  Source IP: " << source_ip << std::endl;
    std::cout << "  Destination IP: " << dest_ip << std::endl;
}
