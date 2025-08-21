# server_api.py
# A simple web API using Flask to serve a list of available VPN servers.
#
# How to run:
# > python server_api.py

from flask import Flask, jsonify

# --- Configuration ---
# In a real application, this list would come from a database.
# For now, we will hardcode it.
VPN_SERVERS = [
    {
        "id": 1,
        "location": "USA - New York",
        "ip": "192.0.2.1" # Replace with your actual server IP
    },
    {
        "id": 2,
        "location": "Germany - Frankfurt",
        "ip": "198.51.100.1" # Replace with your actual server IP
    },
    {
        "id": 3,
        "location": "Japan - Tokyo",
        "ip": "203.0.113.1" # Replace with your actual server IP
    }
]

app = Flask(__name__)

@app.route('/servers', methods=['GET'])
def get_servers():
    """
    The API endpoint that returns the list of VPN servers.
    """
    return jsonify(VPN_SERVERS)

if __name__ == '__main__':
    # Runs the API server on http://0.0.0.0:5000
    # '0.0.0.0' makes it accessible from other machines on the network.
    app.run(host='0.0.0.0', port=5000)
