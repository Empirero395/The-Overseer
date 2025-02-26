def xor_encode(data: str, key: int) -> list[int]:
    key_byte = key if isinstance(key, int) else int(key, 16)
    return [ord(char) ^ key_byte for char in data]

encode = ""
KEY = 0x55

encoded_webhook = xor_encode(encode, KEY)
print(encoded_webhook)

decoded_webhook = "".join(chr(x ^ KEY) for x in encoded_webhook)