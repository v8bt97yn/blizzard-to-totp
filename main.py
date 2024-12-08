import requests
import base64
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

def hex_to_base32(hex_str):
    # Convert hex string to bytes
    raw_bytes = bytes.fromhex(hex_str)
    # Convert bytes to Base32 (RFC4648)
    b32_encoded = base64.b32encode(raw_bytes).decode('utf-8')
    return b32_encoded

def run_process():
    sso_token = entry_sso_token.get().strip()
    if not sso_token:
        messagebox.showerror("Error", "Please enter an SSO token.")
        return
    
    text_log.delete('1.0', tk.END)  # Clear previous logs
    text_log.insert(tk.END, "[*] Obtaining Bearer Token...\n")

    # Step 2: Get Bearer Token
    bearer_url = "https://oauth.battle.net/oauth/sso"
    bearer_payload = {
        "client_id": "baedda12fe054e4abdfc3ad7bdea970a",
        "grant_type": "client_sso",
        "scope": "auth.authenticator",
        "token": sso_token
    }
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8"
    }

    try:
        bearer_response = requests.post(bearer_url, data=bearer_payload, headers=headers)
    except requests.RequestException as e:
        text_log.insert(tk.END, f"[!] Request exception: {e}\n")
        return

    if bearer_response.status_code != 200:
        text_log.insert(tk.END, f"[!] Failed to obtain Bearer Token. Response:\n{bearer_response.text}\n")
        return

    bearer_data = bearer_response.json()
    access_token = bearer_data.get("access_token")
    if not access_token:
        text_log.insert(tk.END, "[!] No access_token found in the response.\n")
        return

    text_log.insert(tk.END, "[+] Bearer Token obtained successfully.\n")

    # Step 3: Attach Authenticator
    text_log.insert(tk.END, "[*] Attaching Authenticator...\n")
    attach_url = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator"
    attach_headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        attach_response = requests.post(attach_url, headers=attach_headers)
    except requests.RequestException as e:
        text_log.insert(tk.END, f"[!] Request exception: {e}\n")
        return

    if attach_response.status_code != 200:
        text_log.insert(tk.END, f"[!] Failed to attach Authenticator. Response:\n{attach_response.text}\n")
        return

    attach_data = attach_response.json()
    serial = attach_data.get("serial")
    restore_code = attach_data.get("restoreCode")
    device_secret_hex = attach_data.get("deviceSecret")

    if not device_secret_hex:
        text_log.insert(tk.END, "[!] No deviceSecret found in the response.\n")
        return

    text_log.insert(tk.END, "[+] Authenticator attached successfully.\n")
    text_log.insert(tk.END, f"    Serial: {serial}\n")
    text_log.insert(tk.END, f"    Restore Code: {restore_code}\n")
    text_log.insert(tk.END, f"    Device Secret (hex): {device_secret_hex}\n")

    # Step 4: Convert Device Secret to Base32 and Print TOTP URL
    text_log.insert(tk.END, "[*] Converting Device Secret from hex to Base32...\n")
    device_secret_b32 = hex_to_base32(device_secret_hex)
    totp_url = f"otpauth://totp/Battle.net?secret={device_secret_b32}&digits=8"

    text_log.insert(tk.END, "[+] Conversion successful!\n")
    text_log.insert(tk.END, f"    Base32 Device Secret: {device_secret_b32}\n")
    text_log.insert(tk.END, f"    TOTP URL: {totp_url}\n")
    text_log.insert(tk.END, "\nUse the above TOTP URL in your authenticator app.\n")


# Set up the GUI
root = tk.Tk()
root.title("Battle.net Authenticator Automation")

# Frame for input
frame_input = ttk.Frame(root, padding="10")
frame_input.pack(fill=tk.X, pady=5)

label_sso = ttk.Label(frame_input, text="SSO Token:")
label_sso.pack(side=tk.LEFT, padx=(0,10))

entry_sso_token = ttk.Entry(frame_input, width=80)
entry_sso_token.pack(side=tk.LEFT, expand=True, fill=tk.X)

btn_run = ttk.Button(frame_input, text="Run", command=run_process)
btn_run.pack(side=tk.LEFT, padx=10)

# Frame for logs
frame_log = ttk.Frame(root, padding="10")
frame_log.pack(fill=tk.BOTH, expand=True)

text_log = tk.Text(frame_log, wrap="word", height=20)
text_log.pack(fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(frame_log, orient=tk.VERTICAL, command=text_log.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_log.config(yscrollcommand=scrollbar.set)

root.mainloop()
