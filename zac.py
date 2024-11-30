import ecdsa
import hashlib
import base58
import time
import requests
from flask import Flask
from keep_alive import keep_alive

keep_alive()

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

def send_to_discord(content):
    webhook_url = 'https://discord.com/api/webhooks/1312495509361004555/pAmdxrGXhAGLFk2cFBEgUhH2taxKAfM6dYSxEQpqpLg9q1f2j8ukDPmIaYm88l5IrQS5'
    data = {
        "content": content
    }
    
    try:
        response = requests.post(webhook_url, json=data)
        response.raise_for_status()
        time.sleep(0.2)
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Discord: {e}")

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x02' + vk.to_string()[:32] if vk.to_string()[32] % 2 == 0 else b'\x03' + vk.to_string()[:32]

def public_key_to_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prepend_network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address = base58.b58encode(prepend_network_byte + checksum)
    return address.decode()

def main():
    start = int("4000000000000000000000000000000000", 16)
    end = start + 10000000

    target_pubkey = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
    target_address = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"

    print(f"Starting search in reverse from: {hex(end)} to {hex(start)}")
    send_to_discord(f"Starting search in reverse from: {hex(end)} to {hex(start)}")

    start_time = time.time()

    for private_key in range(end - 1, start - 1, -1):  # Reversed range
        if private_key % 10000 == 0:
            send_to_discord(f"Checking private key {hex(private_key)}")

        public_key = private_key_to_public_key(private_key)
        public_key_hex = public_key.hex()

        if public_key_hex == target_pubkey:
            wallet_address = public_key_to_address(public_key)

            if wallet_address == target_address:
                found_message = f"@everyone Found matching private key: {hex(private_key)}"
                send_to_discord(found_message)
                break

        if private_key % 100000 == 0:
            elapsed_time = time.time() - start_time
            elapsed_message = f"Elapsed time: {elapsed_time:.2f} seconds"
            send_to_discord(elapsed_message)

if __name__ == "__main__":
    main()
