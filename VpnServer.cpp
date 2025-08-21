// vpn_server.cpp
// A foundational C++ program for the server-side of our VPN.
// It listens for a client, receives raw IP packets, and forwards them using a raw socket.
//
// How to compile (on Linux with g++):
// > g++ vpn_server.cpp -o vpn_server -lpthread
//
// How to run (on Linux):
// > sudo ./vpn_server 
// (Root permissions are required to create raw sockets)

#ifdef _WIN32
    #error This server code is designed for Linux for raw socket forwarding.
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else // For Linux/macOS
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h> // For IP header structure
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

    SOCKET listenSocket = INVALID_SOCKET;
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed." << std::endl;
        return 1;
    }

    // Allow socket reuse
    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind the socket to an IP address and port
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    serverAddr.sin_port = htons(8888); // Port 8888

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed." << std::endl;
        closesocket(listenSocket);
        return 1;
    }

    // Start listening for client connections
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Listen failed." << std::endl;
        closesocket(listenSocket);
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
        
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        getpeername(clientSocket, (struct sockaddr*)&client_addr, &client_len);
        std::cout << "[INFO] Client connected from " << inet_ntoa(client_addr.sin_addr) << ". Starting handler thread..." << std::endl;
        
        // Create a new thread to handle the client
        std::thread clientThread(handle_client, clientSocket);
        clientThread.detach(); // Detach the thread to run independently
    }

    // Cleanup
    closesocket(listenSocket);
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

            // --- REAL FORWARDING LOGIC ---
            // 1. Create a raw socket to send the packet to the internet.
            SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (rawSocket == INVALID_SOCKET) {
                perror("[ERROR] Failed to create raw socket. Are you root?");
                continue;
            }

            // 2. Get the destination address from the packet header.
            struct iphdr* ip_header = (struct iphdr*)buffer.data();
            sockaddr_in destAddr;
            destAddr.sin_family = AF_INET;
            destAddr.sin_addr.s_addr = ip_header->daddr;

            // 3. Send the packet.
            if (sendto(rawSocket, buffer.data(), bytes_received, 0, (struct sockaddr*)&destAddr, sizeof(destAddr)) < 0) {
                perror("[ERROR] sendto failed on raw socket");
                closesocket(rawSocket);
                continue;
            }
            std::cout << "  [FORWARD] Packet sent to destination." << std::endl;
            
            // 4. Wait for the response on the same raw socket.
            // NOTE: This is a simplified approach. A production VPN would use a more
            // sophisticated method (like libpcap or full NAT) to handle responses.
            std::vector<unsigned char> recv_buffer(BUFFER_SIZE);
            int response_bytes = recvfrom(rawSocket, (char*)recv_buffer.data(), BUFFER_SIZE, 0, NULL, NULL);

            if (response_bytes > 0) {
                 std::cout << "  [RESPONSE] Received " << response_bytes << " bytes from destination." << std::endl;
                 // 5. Send the response back to the client.
                 if (send(clientSocket, (char*)recv_buffer.data(), response_bytes, 0) < 0) {
                     perror("[ERROR] Failed to send response back to client");
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
 * @brief Prints basic information about a captured IP packet. (Same as client)
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
