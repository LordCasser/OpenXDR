package realip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolve(t *testing.T) {
	trusted, err := Parse("10.1.1.197, 10.1.1.198/32, 10.1.1.100, 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"经网关、nginx、haproxy", "10.1.1.198:51234", []string{"10.1.1.35, 10.1.1.100"}, "10.1.1.35"},
		{"直连控制台 nginx", "10.1.1.197:40000", []string{"10.1.1.36"}, "10.1.1.36"},
		{"客户端伪造的头在最左边", "10.1.1.198:1", []string{"6.6.6.6, 10.1.1.35, 10.1.1.100"}, "10.1.1.35"},
		{"多个头按顺序拼接", "10.1.1.198:1", []string{"10.1.1.35", "10.1.1.100"}, "10.1.1.35"},
		{"直连方不可信不还原", "10.1.1.50:1", []string{"10.1.1.35"}, ""},
		{"没有转发头", "10.1.1.198:1", nil, ""},
		{"链路全是可信代理", "10.1.1.198:1", []string{"10.1.1.100"}, ""},
		{"非地址的值不还原", "10.1.1.198:1", []string{"unknown"}, ""},
		{"IPv4 映射地址", "[::ffff:10.1.1.198]:1", []string{"10.1.1.35"}, "10.1.1.35"},
	}
	for _, c := range cases {
		if got := resolve(c.remote, c.xff, trusted); got != c.want {
			t.Errorf("%s：得到 %q，期望 %q", c.name, got, c.want)
		}
	}
	if _, err := Parse("10.1.1.0/33"); err == nil {
		t.Error("非法网段应报错")
	}
}

func TestMiddleware(t *testing.T) {
	var seen string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.RemoteAddr })
	trusted, _ := Parse("127.0.0.1")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:9000"
	r.Header.Set("X-Forwarded-For", "10.1.1.35")
	Middleware(trusted, h).ServeHTTP(httptest.NewRecorder(), r)
	if seen != "10.1.1.35:0" {
		t.Errorf("可信代理转发应还原客户端地址，得到 %q", seen)
	}

	r.RemoteAddr = "127.0.0.1:9000"
	Middleware(nil, h).ServeHTTP(httptest.NewRecorder(), r)
	if seen != "127.0.0.1:9000" {
		t.Errorf("未配置可信代理时应原样放行，得到 %q", seen)
	}
}
