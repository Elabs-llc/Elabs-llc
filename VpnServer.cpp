// vpn_server.cpp
// A foundational C++ program for the server-side of our VPN.
// It listens for a client, receives raw IP packets, and prints their info.
//
// How to compile (using MSVC compiler from a Developer Command Prompt):
// > cl.exe vpn_server.cpp /EHsc ws2_32.lib
//
// How to compile (on Linux with g++):
// > g++ vpn_server.cpp -o vpn_server -lpthread

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else // For Linux/macOS
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

#include <iostream>
#include <vector>
#include <thread>

// --- Function Prototypes ---
void print_packet_info(const unsigned char* buffer, int len);
void handle_client(SOCKET clientSocket);

// --- Main Application Entry Point ---
int main() {
    std::cout << "--- C++ VPN Server ---" << std::endl;

#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[ERROR] WSAStartup failed: " << result << std::endl;
        return 1;
    }
    std::cout << "[INFO] Winsock initialized." << std::endl;
#endif

    SOCKET listenSocket = INVALID_SOCKET;
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed." << std::endl;
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }

    // Bind the socket to an IP address and port
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    serverAddr.sin_port = htons(8888); // Port 8888

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed." << std::endl;
        closesocket(listenSocket);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }

    // Start listening for client connections
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Listen failed." << std::endl;
        closesocket(listenSocket);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 1;
    }

    std::cout << "[INFO] Server listening on port 8888..." << std::endl;

    // Accept client connections in a loop
    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "[WARNING] Accept failed." << std::endl;
            continue;
        }
        
        std::cout << "[INFO] Client connected. Starting handler thread..." << std::endl;
        // Create a new thread to handle the client
        std::thread clientThread(handle_client, clientSocket);
        clientThread.detach(); // Detach the thread to run independently
    }

    // Cleanup
    closesocket(listenSocket);
    #ifdef _WIN32
    WSACleanup();
    #endif

    return 0;
}

/**
 * @brief Handles the communication with a single connected client.
 *
 * @param clientSocket The socket for the connected client.
 */
void handle_client(SOCKET clientSocket) {
    const int BUFFER_SIZE = 2048;
    std::vector<unsigned char> buffer(BUFFER_SIZE);

    while (true) {
        int bytes_received = recv(clientSocket, (char*)buffer.data(), BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            std::cout << "\n--- Received Packet from Client (" << bytes_received << " bytes) ---" << std::endl;
            print_packet_info(buffer.data(), bytes_received);

            // --- FORWARDING LOGIC (Placeholder) ---
            // In a real VPN, you would:
            // 1. Decrypt this packet.
            // 2. Open a raw socket on the server.
            // 3. Send the packet to its original destination on the internet.
            // 4. Receive the response via the raw socket.
            // 5. Encrypt the response.
            // 6. Send the encrypted response back to the client via clientSocket.

            // For now, we'll just echo a simple message back.
            const char* response = "Packet Received";
            send(clientSocket, response, strlen(response), 0);

        } else if (bytes_received == 0) {
            std::cout << "[INFO] Client disconnected." << std::endl;
            break;
        } else {
            std::cerr << "[ERROR] recv failed." << std::endl;
            break;
        }
    }

    closesocket(clientSocket);
}


/**
 * @brief Prints basic information about a captured IP packet. (Same as client)
 */
void print_packet_info(const unsigned char* buffer, int len) {
    if (len < 20) {
        std::cout << "  Packet too small to be a valid IP packet." << std::endl;
        return;
    }
    unsigned char ip_version = (buffer[0] >> 4);
    std::cout << "  IP Version: " << (int)ip_version << std::endl;
    std::cout << "  Source IP: " << (int)buffer[12] << "." << (int)buffer[13] << "." << (int)buffer[14] << "." << (int)buffer[15] << std::endl;
    std::cout << "  Destination IP: " << (int)buffer[16] << "." << (int)buffer[17] << "." << (int)buffer[18] << "." << (int)buffer[19] << std::endl;
}
