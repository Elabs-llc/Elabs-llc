My Professional VPN
A complete, end-to-end VPN software solution built from the ground up using C++ and Python. This project provides a secure, encrypted tunnel for all your internet traffic, featuring a robust backend, a background Windows service, and a user-friendly graphical interface. It's designed as a comprehensive, educational example of how professional VPNs are engineered.

Features
Secure Encrypted Tunnel: Utilizes TLS 1.2+ for a secure handshake and AES-256 for symmetric encryption of all network traffic between the client and server.

Low-Level Packet Capture: The C++ client core uses a TAP virtual network adapter on Windows to capture all outgoing IP packets at the kernel level, ensuring all applications are routed through the VPN.

Background Windows Service: The C++ client runs as a persistent, silent Windows Service, providing a stable connection that runs independently of the user interface.

Graphical User Interface (GUI): A clean and simple UI built with Python and Tkinter allows users to enter credentials, select server locations, and connect/disconnect with ease.

Dynamic Server List: The client fetches an up-to-date list of available server locations from a central Flask-based web API, allowing for easy server management.

Professional Kill Switch: Implements a robust kill switch using the Windows Filtering Platform (WFP). It instantly blocks all non-VPN traffic if the connection drops, preventing any IP or data leaks.

Cross-Platform Server: The core server logic is written in C++ and is designed to run on Linux, the standard for professional VPN infrastructure.

Technology Stack
Client Core: C++

Server Core: C++

User Interface: Python 3, Tkinter

Server List API: Python 3, Flask

Cryptography: OpenSSL (for TLS and AES-256)

Windows Networking: TAP-Windows Driver, Windows Filtering Platform (WFP)

Server Networking: Raw Sockets (Linux)

How to Build and Run
Prerequisites
Server (Linux): g++, libssl-dev

Client (Windows): Visual Studio with C++ tools, OpenSSL for Windows, TAP-Windows Driver

UI (Windows): Python 3, requests, pyinstaller (for creating an executable)

API Server: Python 3, flask

1. The VPN Server (Linux)
Generate a self-signed certificate: openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

Place key.pem and cert.pem in the server directory.

Compile the server: g++ vpn_server.cpp -o vpn_server -lpthread -lssl -lcrypto

Run the server with root privileges: sudo ./vpn_server

2. The Client Service (Windows)
Compile the C++ service (vpn_service.cpp) using the MSVC compiler command provided in the source file. This will create vpn_service.exe.

Create a directory, e.g., C:\MyVPN\, and place vpn_service.exe inside it.

Open an Administrator Command Prompt.

Install the service: sc create MyVPNService binPath= "C:\MyVPN\vpn_service.exe"

3. The Server List API
Update the VPN_SERVERS list in server_api.py with your server locations and public IPs.

Run the API server: python server_api.py

4. The Client UI (Windows)
Update the API_URL and CONFIG_PATH variables in vpn_ui.py.

Run the UI with Administrator privileges (required to control the Windows Service): python vpn_ui.py

Enter your credentials, select a server, and click Connect. This will write to the config.ini file and start the MyVPNService.

Security Notes
This project uses a hardcoded user (user:pass) for authentication. For a production system, the server should be modified to check credentials against a secure database.

The TLS handshake ensures that a unique session key is generated for every connection, providing strong forward secrecy.

The kill switch is designed to be persistent. If the service is not stopped gracefully, the "Block All" rule will remain active, ensuring the user is protected until the service is restarted.

Future Improvements
Database Integration: Replace the hardcoded user with a proper user database (e.g., SQLite or MySQL) on the server.

Kill Switch Integration: Fully integrate the vpn_killswitch.cpp logic into the vpn_service.cpp file.

UI Enhancements: Add real-time bandwidth monitoring and a more detailed connection status.

Installer: Create a Windows installer (e.g., using Inno Setup) to automate the installation of the TAP driver, the service, and the UI.
