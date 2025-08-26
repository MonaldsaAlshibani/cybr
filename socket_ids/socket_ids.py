"""
Socket Project with Simple IDS + Full Traffic Logging
Authors: Mohammed Agila , Islam Alsigoutri,Mohammed Alshibani
"""

import socket
import datetime


SUSPICIOUS_KEYWORDS = ["attack", "hack", "virus", "malware"]
LOG_FILE = "ids_log.txt"


def log_activity(addr, message, suspicious=False):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        status = "SUSPICIOUS" if suspicious else "NORMAL"
        log_entry = f"[{datetime.datetime.now()}] {status} traffic from {addr} | Message: {message}\n"
        f.write(log_entry)



def start_server(host="127.0.0.1", port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"[{datetime.datetime.now()}] Server started on {host}:{port}")
    print("Waiting for connections...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")


        message = client_socket.recv(1024).decode("utf-8")
        print(f"Client says: {message}")

       
        alert = any(word in message.lower() for word in SUSPICIOUS_KEYWORDS)
        if alert:
            warning = f"[ALERT] Suspicious activity detected from {addr} at {datetime.datetime.now()}"
            print(warning)
            log_activity(addr, message, suspicious=True)
            reply = "⚠️ Warning: Your message triggered the IDS! (Logged)"
        else:
            log_activity(addr, message, suspicious=False)
            reply = f"✅ Server Response: '{message}' received at {datetime.datetime.now()}"

      
        client_socket.send(reply.encode("utf-8"))
        client_socket.close()



def start_client(host="127.0.0.1", port=12345):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    msg = input("Enter a message for the server: ")
    client_socket.send(msg.encode("utf-8"))

    reply = client_socket.recv(1024).decode("utf-8")
    print(f"Server replied: {reply}")

    client_socket.close()



if __name__ == "__main__":
    choice = input("Run as (s)erver or (c)lient? ")
    if choice.lower().startswith("s"):
        start_server()
    else:
        start_client()