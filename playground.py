import ssl, socket

host = "example.com"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, 443), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        print("TLS version:", ssock.version())
        print("Cipher:", ssock.cipher())
        der = ssock.getpeercert(binary_form=True)
        print("Leaf cert bytes:", len(der) if der else None)
