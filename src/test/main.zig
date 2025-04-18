const ipcrypt = @cImport(@cInclude("ipcrypt2.h"));

const std = @import("std");
const testing = std.testing;

test "ip string encryption and decryption" {
    const key = "0123456789abcdef";
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    const ip_str = "1.2.3.4";

    var encrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];

    const expected_encrypted_ip = "9f4:e6e1:c77e:ffe8:49ac:6a6a:9f11:620f";
    try testing.expectEqualSlices(u8, expected_encrypted_ip, encrypted_ip);

    var decrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const decrypted_ip_len = ipcrypt.ipcrypt_decrypt_ip_str(&st, &decrypted_ip_buf, encrypted_ip.ptr);
    const decrypted_ip_str = decrypted_ip_buf[0..decrypted_ip_len];
    try testing.expectEqualSlices(u8, ip_str, decrypted_ip_str);
}

test "ip string non-deterministic encryption and decryption" {
    const key = "0123456789abcdef";
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    const ip_str = "1.2.3.4";
    const tweak: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_nd_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];

    const expected_encrypted_ip = "01020304050607085f8ec3223eaa68378ba06d3bc3df0209";
    try testing.expectEqualSlices(u8, expected_encrypted_ip, encrypted_ip);

    var decrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const decrypted_ip_len = ipcrypt.ipcrypt_nd_decrypt_ip_str(&st, &decrypted_ip_buf, encrypted_ip.ptr);
    const decrypted_ip_str = decrypted_ip_buf[0..decrypted_ip_len];
    try testing.expectEqualSlices(u8, ip_str, decrypted_ip_str);
}

test "binary ip deterministic encryption and decryption" {
    const expected_ip: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const key = "0123456789abcdef";
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    var ip: [16]u8 = expected_ip;
    ipcrypt.ipcrypt_encrypt_ip16(&st, &ip);
    ipcrypt.ipcrypt_decrypt_ip16(&st, &ip);
    try testing.expectEqualSlices(u8, &expected_ip, &ip);
}

test "binary ip non-deterministic encryption and decryption" {
    const ip: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const key = "0123456789abcdef";
    const tweak: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    var encrypted_ip: [ipcrypt.IPCRYPT_NDIP_BYTES]u8 = undefined;
    ipcrypt.ipcrypt_nd_encrypt_ip16(&st, &encrypted_ip, &ip, &tweak);
    var decrypted_ip: [16]u8 = undefined;
    ipcrypt.ipcrypt_nd_decrypt_ip16(&st, &decrypted_ip, &encrypted_ip);
    try testing.expectEqualSlices(u8, &ip, &decrypted_ip);
}

test "equivalence between AES and KIASU-BC with tweak=0*" {
    const ip: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const key = "0123456789abcdef";
    const tweak: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };

    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, key);
    defer ipcrypt.ipcrypt_deinit(&st);

    var encrypted_ip: [ipcrypt.IPCRYPT_NDIP_BYTES]u8 = undefined;
    ipcrypt.ipcrypt_nd_encrypt_ip16(&st, &encrypted_ip, &ip, &tweak);

    var encrypted_ip2 = ip;
    ipcrypt.ipcrypt_encrypt_ip16(&st, &encrypted_ip2);

    try testing.expectEqualSlices(u8, encrypted_ip[ipcrypt.IPCRYPT_TWEAKBYTES..], &encrypted_ip2);
}

test "binary ip NDX encryption and decryption" {
    const ip: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const key = "0123456789abcdef1032547698badcfe";
    const tweak: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    var st: ipcrypt.IPCryptNDX = undefined;
    ipcrypt.ipcrypt_ndx_init(&st, key);
    defer ipcrypt.ipcrypt_ndx_deinit(&st);
    var encrypted_ip: [ipcrypt.IPCRYPT_NDX_NDIP_BYTES]u8 = undefined;
    ipcrypt.ipcrypt_ndx_encrypt_ip16(&st, &encrypted_ip, &ip, &tweak);
    var decrypted_ip: [16]u8 = undefined;
    ipcrypt.ipcrypt_ndx_decrypt_ip16(&st, &decrypted_ip, &encrypted_ip);
    try testing.expectEqualSlices(u8, &ip, &decrypted_ip);
}

test "ip string NDX encryption and decryption" {
    const key = "0123456789abcdef1032547698badcfe";
    var st: ipcrypt.IPCryptNDX = undefined;
    ipcrypt.ipcrypt_ndx_init(&st, key);
    defer ipcrypt.ipcrypt_ndx_deinit(&st);

    const ip_str = "1.2.3.4";
    const tweak: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDX_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_ndx_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];

    const expected_encrypted_ip = "0102030405060708090a0b0c0d0e0f10a472dd736f82eb599b85141580b21c40";
    try testing.expectEqualSlices(u8, expected_encrypted_ip, encrypted_ip);

    var decrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const decrypted_ip_len = ipcrypt.ipcrypt_ndx_decrypt_ip_str(&st, &decrypted_ip_buf, encrypted_ip.ptr);
    const decrypted_ip_str = decrypted_ip_buf[0..decrypted_ip_len];
    try testing.expectEqualSlices(u8, ip_str, decrypted_ip_str);
}

test "test vector for ipcrypt-deterministic" {
    const key_hex = "0123456789abcdeffedcba9876543210";
    const ip_str = "0.0.0.0";
    const expected = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb";
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, &key);
    defer ipcrypt.ipcrypt_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_MAX_IP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 1 for ipcrypt-nd" {
    const key_hex = "0123456789abcdeffedcba9876543210";
    const ip_str = "0.0.0.0";
    const expected = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16";
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "08e0c289bff23b7c";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, &key);
    defer ipcrypt.ipcrypt_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_nd_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 2 for ipcrypt-nd" {
    const key_hex = "1032547698badcfeefcdab8967452301";
    const ip_str = "192.0.2.1";
    const expected = "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad";
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "21bd1834bc088cd2";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, &key);
    defer ipcrypt.ipcrypt_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_nd_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 3 for ipcrypt-nd" {
    const key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const ip_str = "2001:db8::1";
    const expected = "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96";
    var key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "b4ecbe30b70898d7";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCrypt = undefined;
    ipcrypt.ipcrypt_init(&st, &key);
    defer ipcrypt.ipcrypt_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_nd_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 1 for ipcrypt-ndx" {
    const key_hex = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301";
    const ip_str = "0.0.0.0";
    const expected = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5";
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "21bd1834bc088cd2b4ecbe30b70898d7";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCryptNDX = undefined;
    ipcrypt.ipcrypt_ndx_init(&st, &key);
    defer ipcrypt.ipcrypt_ndx_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDX_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_ndx_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 2 for ipcrypt-ndx" {
    const key_hex = "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210";
    const ip_str = "192.0.2.1";
    const expected = "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a";
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "08e0c289bff23b7cb4ecbe30b70898d7";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCryptNDX = undefined;
    ipcrypt.ipcrypt_ndx_init(&st, &key);
    defer ipcrypt.ipcrypt_ndx_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDX_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_ndx_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "test vector 3 for ipcrypt-ndx" {
    const key_hex = "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b";
    const ip_str = "2001:db8::1";
    const expected = "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4";
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const tweak_hex = "21bd1834bc088cd2b4ecbe30b70898d7";
    var tweak: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    var st: ipcrypt.IPCryptNDX = undefined;
    ipcrypt.ipcrypt_ndx_init(&st, &key);
    defer ipcrypt.ipcrypt_ndx_deinit(&st);
    var encrypted_ip_buf: [ipcrypt.IPCRYPT_NDX_NDIP_STR_BYTES:0]u8 = undefined;
    const encrypted_ip_len = ipcrypt.ipcrypt_ndx_encrypt_ip_str(&st, &encrypted_ip_buf, ip_str, &tweak);
    const encrypted_ip = encrypted_ip_buf[0..encrypted_ip_len];
    try testing.expectEqualSlices(u8, expected, encrypted_ip);
}

test "socket address conversion" {
    // Test IPv4-mapped IPv6 address (1.2.3.4)
    const ipv4_mapped: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };

    // Convert to sockaddr_storage (use a byte array of sufficient size)
    var sa: [128]u8 = undefined; // 128 bytes is enough for any sockaddr_storage
    ipcrypt.ipcrypt_ip16_to_sockaddr(@ptrCast(@alignCast(&sa)), &ipv4_mapped);

    // Convert back to 16-byte IP
    var ip16: [16]u8 = undefined;
    try testing.expectEqual(0, ipcrypt.ipcrypt_sockaddr_to_ip16(&ip16, @ptrCast(@alignCast(&sa))));

    // Verify the result matches the original
    try testing.expectEqualSlices(u8, &ipv4_mapped, &ip16);

    // Test IPv6 address (2001:db8::1)
    const ipv6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    // Convert to sockaddr_storage
    ipcrypt.ipcrypt_ip16_to_sockaddr(@ptrCast(@alignCast(&sa)), &ipv6);

    // Convert back to 16-byte IP
    try testing.expectEqual(0, ipcrypt.ipcrypt_sockaddr_to_ip16(&ip16, @ptrCast(@alignCast(&sa))));

    // Verify the result matches the original
    try testing.expectEqualSlices(u8, &ipv6, &ip16);
}

test "key from hex conversion" {
    // Test valid 16-byte key
    const hex16 = "0123456789abcdef0123456789abcdef";
    var key16: [16]u8 = undefined;
    try testing.expectEqual(0, ipcrypt.ipcrypt_key_from_hex(&key16, key16.len, hex16, hex16.len));
    const expected_key16: [16]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    try testing.expectEqualSlices(u8, &expected_key16, &key16);

    // Test valid 32-byte key
    const hex32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var key32: [32]u8 = undefined;
    try testing.expectEqual(0, ipcrypt.ipcrypt_key_from_hex(&key32, key32.len, hex32, hex32.len));
    const expected_key32: [32]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    try testing.expectEqualSlices(u8, &expected_key32, &key32);

    // Test invalid hex length
    const invalid_hex = "0123456789abcdef";
    var key: [16]u8 = undefined;
    try testing.expectEqual(-1, ipcrypt.ipcrypt_key_from_hex(&key, key.len, invalid_hex, invalid_hex.len));

    // Test invalid hex characters
    const invalid_chars = "0123456789abcdef0123456789abcdeg";
    try testing.expectEqual(-1, ipcrypt.ipcrypt_key_from_hex(&key, key.len, invalid_chars, invalid_chars.len));
}
