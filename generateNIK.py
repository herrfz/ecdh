from ECDiffieHellman import ECDH

dh = ECDH()

private_key = dh.gen_private_key()
public_key = dh.gen_public_key(private_key)

# serialize public key

# send public key

# wait until other's public key is received

# check if public key is ok

# generate shared secret and NIK

# report