// vpn_server.cpp
// The secure C++ VPN server with TLS for authentication and key exchange.
//
// How to compile (on Linux with g++):
// > g++ vpn_server.cpp -o vpn_server -lpthread -lssl -lcrypto
//
// How to run (on Linux):
// > sudo ./vpn_server 
// (Requires root for raw sockets and cert/key file access)
//
// Prerequisites:
// 1. libssl-dev installed.
// 2. "cert.pem" and "key.pem" files in the same directory.

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close

// --- Function Prototypes ---
void handle_client(SOCKET clientSocket, SSL_CTX *ctx);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);

// --- Main Application Entry Point ---
int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    std::cout << "--- C++ VPN Server (with TLS Authentication) ---" << std::endl;

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // ... (socket creation, bind, listen logic remains the same as before)
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
            perror("Accept failed");
            continue;
        }
        std::thread clientThread(handle_client, clientSocket, ctx);
        clientThread.detach();
    }

    closesocket(listenSocket);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Load the server certificate
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Load the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handle_client(SOCKET clientSocket, SSL_CTX *ctx) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "[INFO] TLS handshake successful." << std::endl;

        // --- AUTHENTICATION ---
        char auth_buffer[128];
        int bytes = SSL_read(ssl, auth_buffer, sizeof(auth_buffer) - 1);
        auth_buffer[bytes] = '\0';
        std::string credentials(auth_buffer);
        
        // Simple hardcoded authentication
        if (credentials == "user:pass") {
            std::cout << "[INFO] Client authenticated successfully." << std::endl;
            SSL_write(ssl, "OK", 2);

            // --- Main Packet Forwarding Loop (now inside authenticated session) ---
            // This logic remains the same, but uses SSL_read/SSL_write
            // For simplicity, this example will just echo packets back.
            // The raw socket forwarding logic from the previous step would go here.
             char packet_buffer[2048];
             while ((bytes = SSL_read(ssl, packet_buffer, sizeof(packet_buffer))) > 0) {
                 std::cout << "[INFO] Received " << bytes << " bytes from client." << std::endl;
                 // Forwarding logic would go here...
                 // Echoing back for demonstration
                 SSL_write(ssl, packet_buffer, bytes);
             }

        } else {
            std::cout << "[WARNING] Client authentication failed." << std::endl;
            SSL_write(ssl, "FAIL", 4);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(clientSocket);
}
