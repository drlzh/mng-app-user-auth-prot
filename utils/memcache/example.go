//go:build ignore

package memcache

func example() {
	mc := New("10.0.0.1:11211", "10.0.0.2:11211", "10.0.0.3:11212")
	_ = mc.Set(&Item{Key: "foo", Value: []byte("my value")})
	_, _ = mc.Get("foo")
}
