import socket, random, string
host = ''.join(random.choices(string.ascii_lowercase+string.digits, k=60)) + ".example.com"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'\x00'*20, ("8.8.8.8", 53))
print("Sent dummy UDP packet; real DNS crafting best via scapy/dig")