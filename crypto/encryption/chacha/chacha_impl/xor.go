package chacha_impl

// addXor reads a little endian uint32 from src, XORs it with (a + b) and
// places the result in little endian byte order in dst.
func addXor(dst, src []byte, a, b uint32) {
	_, _ = src[3], dst[3] // bounds check elimination hint
	a += b
	dst[0] = src[0] ^ byte(a)
	dst[1] = src[1] ^ byte(a>>8)
	dst[2] = src[2] ^ byte(a>>16)
	dst[3] = src[3] ^ byte(a>>24)
}
