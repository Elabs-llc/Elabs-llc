# vpn_ui.py
# A Python GUI application to manage the C++ VPN client.
# This script launches the C++ executable with authentication credentials.
#
# Prerequisites:
# 1. Python 3 installed.
# 2. The compiled C++ client (e.g., "tuntap_reader.exe") must be in the same
#    directory as this script.

import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import os

# --- Configuration ---
# The name of your compiled C++ executable
CPP_EXECUTABLE_NAME = "tuntap_reader.exe"

# --- Global Variables ---
vpn_process = None
is_connected = False

# --- Core Functions ---

def connect_vpn():
    """
    Starts the C++ VPN client as a background process, passing credentials.
    """
    global vpn_process, is_connected

    username = user_entry.get()
    password = pass_entry.get()

    if not username or not password:
        messagebox.showwarning("Input Required", "Please enter a username and password.")
        return

    if is_connected:
        log("Already connected.")
        return

    if not os.path.exists(CPP_EXECUTABLE_NAME):
        messagebox.showerror("Error", f"Could not find the VPN core executable:\n'{CPP_EXECUTABLE_NAME}'")
        return

    log(f"Starting VPN core with user '{username}'...")
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        # Pass credentials as command-line arguments to the C++ executable
        vpn_process = subprocess.Popen(
            [CPP_EXECUTABLE_NAME, username, password], 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            text=True
        )
        is_connected = True
        log("VPN Core process started.")
        update_ui_status()
        
        threading.Thread(target=log_subprocess_output, args=(vpn_process.stdout,), daemon=True).start()
        threading.Thread(target=log_subprocess_output, args=(vpn_process.stderr,), daemon=True).start()

    except Exception as e:
        log(f"Failed to start VPN core: {e}")
        messagebox.showerror("Error", f"An error occurred while starting the VPN core:\n{e}")
        is_connected = False
        vpn_process = None
        update_ui_status()

def disconnect_vpn():
    """
    Terminates the C++ VPN client process.
    """
    global vpn_process, is_connected
    if not is_connected or not vpn_process:
        log("Already disconnected.")
        return

    log("Stopping VPN core process...")
    try:
        vpn_process.terminate()
        vpn_process.wait()
        log("VPN Core process stopped.")
    except Exception as e:
        log(f"Error while stopping VPN core: {e}")
    finally:
        is_connected = False
        vpn_process = None
        update_ui_status()

def log_subprocess_output(pipe):
    """
    Reads output from the subprocess pipe and logs it to the GUI.
    """
    try:
        for line in iter(pipe.readline, ''):
            log(f"[Core] {line.strip()}")
        pipe.close()
    except Exception as e:
        log(f"Error reading from core process pipe: {e}")


# --- GUI Functions ---

def log(message):
    """Adds a message to the log window in a thread-safe way."""
    log_area.config(state=tk.NORMAL)
    log_area.insert(tk.END, message + "\n")
    log_area.config(state=tk.DISABLED)
    log_area.see(tk.END)

def update_ui_status():
    """Updates button states and status label based on connection status."""
    if is_connected:
        status_label.config(text="Status: Connected", fg="#2E8B57")
        connect_button.config(state=tk.DISABLED)
        disconnect_button.config(state=tk.NORMAL)
        user_entry.config(state=tk.DISABLED)
        pass_entry.config(state=tk.DISABLED)
    else:
        status_label.config(text="Status: Disconnected", fg="#B22222")
        connect_button.config(state=tk.NORMAL)
        disconnect_button.config(state=tk.DISABLED)
        user_entry.config(state=tk.NORMAL)
        pass_entry.config(state=tk.NORMAL)

def on_closing():
    """Handles window close event."""
    if is_connected:
        disconnect_vpn()
    root.destroy()

# --- GUI Setup ---
root = tk.Tk()
root.title("My Professional VPN")
root.geometry("650x500") # Increased height for login fields
root.configure(bg="#F0F0F0")

main_frame = tk.Frame(root, padx=15, pady=15, bg="#F0F0F0")
main_frame.pack(fill=tk.BOTH, expand=True)

title_label = tk.Label(main_frame, text="My Professional VPN", fg="#333", bg="#F0F0F0", font=("Helvetica", 18, "bold"))
title_label.pack(pady=(0, 10))

# --- Login Frame ---
login_frame = tk.Frame(main_frame, bg="#F0F0F0")
login_frame.pack(pady=10)

tk.Label(login_frame, text="Username:", bg="#F0F0F0", font=("Helvetica", 10)).grid(row=0, column=0, sticky="w", padx=5)
user_entry = tk.Entry(login_frame, font=("Helvetica", 10), width=25)
user_entry.grid(row=0, column=1, pady=2)
user_entry.insert(0, "user") # Default value for testing

tk.Label(login_frame, text="Password:", bg="#F0F0F0", font=("Helvetica", 10)).grid(row=1, column=0, sticky="w", padx=5)
pass_entry = tk.Entry(login_frame, show="*", font=("Helvetica", 10), width=25)
pass_entry.grid(row=1, column=1, pady=2)
pass_entry.insert(0, "pass") # Default value for testing

status_label = tk.Label(main_frame, text="Status: Disconnected", fg="#B22222", bg="#F0F0F0", font=("Helvetica", 14, "bold"))
status_label.pack(pady=10)

button_frame = tk.Frame(main_frame, bg="#F0F0F0")
button_frame.pack(pady=15)

connect_button = tk.Button(button_frame, text="Connect", command=lambda: threading.Thread(target=connect_vpn).start(), font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="white", relief=tk.FLAT, padx=20, pady=5)
connect_button.pack(side=tk.LEFT, padx=10)

disconnect_button = tk.Button(button_frame, text="Disconnect", command=disconnect_vpn, state=tk.DISABLED, font=("Helvetica", 12, "bold"), bg="#f44336", fg="white", relief=tk.FLAT, padx=20, pady=5)
disconnect_button.pack(side=tk.LEFT, padx=10)

log_frame = tk.LabelFrame(main_frame, text="Connection Log", bg="#F0F0F0", fg="#555", font=("Helvetica", 10))
log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
log_area = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, wrap=tk.WORD, bg="#FFFFFF", relief=tk.SUNKEN, borderwidth=1, font=("Consolas", 9))
log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

if __name__ == "__main__":
    update_ui_status()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
