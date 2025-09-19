def debug_looks_binary(b):
    head = b[:1024]
    print("Head:", repr(head))
    print("NUL check:", b"\x00" in head)
    if b"\x00" in head:
        print("Returning True")
        return True
    ctrl = sum(1 for x in head if x < 9 or (13 < x < 32))
    print("Ctrl count:", ctrl, "Threshold:", max(4, len(head) // 16))
    return ctrl > max(4, len(head) // 16)


test_binary = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
print("Debug result:", debug_looks_binary(test_binary))
