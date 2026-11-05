def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with PKCS#7 padding for `block_size` (see the module docstring)."""
    #raise NotImplementedError("Complete the independent padding warmup")
    with open(data, "rb") as f:
        cnt = 1
        #reading the bytes one at a time
        while (byte := f.read(1)):
            cnt += 1
        rem = cnt % block_size
        app = 0
        if rem == 0:
            app = block_size
        else: 
            app = rem
        for i in range(app):
            data.append(b'{hex(app)}')
    return data


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size should be between 1 and 255")
    elif data == None or data == b'':
        return ValueError("Empty input")
    
    pad_val = int(data[-1].hex(), 0)
    comp = pad_val
    flag = False
    for i in pad_val:
        snatch = (data[-1].hex(), 0)
        if snatch != comp:
            flag = True
            break
        data = data[:-1]
    if flag:
        raise ValueError("Incorrect padding")
    
    return data

'''
getting it to pass the tests, all purely my own work. simplified version is in padding.py:

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with PKCS#7 padding for `block_size` (see the module docstring)."""
    #raise NotImplementedError("Complete the independent padding warmup")
    if block_size < 1 or block_size > 255:
        raise ValueError("Block Size should be between 1 and 255")
    cnt = 0
    for i in range(len(data)):
        cnt+=1
    rem = (cnt) % block_size
    app = 0
    if rem == 0:
        app = block_size
    else: 
        app = block_size - rem
    for i in range(app):
        data += bytes([app])
    return data


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size should be between 1 and 255")
    if not data:
        raise ValueError("Empty input")

    if len(data) % block_size != 0:
        ValueError("Input is not block-aligned")
    
    pad_val = int(data[-1])
    flag = False
    counter = 0
    if pad_val > len(data) or pad_val == 0:
        raise ValueError("Incorrect Padding")
    
    for i in range(pad_val):
        counter+=1
        last_byte = int(data[-1])
        if last_byte != pad_val:
            flag = True
            break
        data = data[:-1]
    if flag or counter != pad_val:
        raise ValueError("Incorrect padding")
    return data
'''