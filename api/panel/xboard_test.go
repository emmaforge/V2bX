package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/InazumaV/V2bX/conf"
)

// Xboard cert_config: cedar2025/Xboard returns it top-level, not merged
// into tls_settings. A panel cert that is only in cert_config must still
// reach CertInfo, otherwise the node silently falls back to local cert.
func TestBuildCertInfoFromXboard(t *testing.T) {
	raw := `{"cert_config":{"mode":"remote","cert_domain":"node.example.com","tls_cert":"CERT","tls_key":"KEY","provider":"manual","email":"a@example.com","dns_env":"CF_TOKEN=abc,CF_ZONE=xyz","reject_unknown_sni":"true","pinned_peer_cert_sha256":"deadbeef"}}`
	var wrap struct {
		CertConfig *XboardCertConfig `json:"cert_config"`
	}
	if err := json.Unmarshal([]byte(raw), &wrap); err != nil {
		t.Fatal(err)
	}
	info := buildCertInfoFromXboard(wrap.CertConfig, nil)
	if info == nil {
		t.Fatal("expected CertInfo, got nil")
	}
	if info.CertMode != "remote" || info.CertDomain != "node.example.com" {
		t.Errorf("mode/domain = %q/%q", info.CertMode, info.CertDomain)
	}
	if info.TlsCert != "CERT" || info.TlsKey != "KEY" {
		t.Errorf("cert/key not parsed: %+v", info)
	}
	if info.DNSEnv["CF_TOKEN"] != "abc" || info.DNSEnv["CF_ZONE"] != "xyz" {
		t.Errorf("dns_env = %v", info.DNSEnv)
	}
	if !info.RejectUnknownSni {
		t.Errorf("reject_unknown_sni should be true")
	}
	if info.PinnedPeerCertSha256 != "deadbeef" {
		t.Errorf("pinned sha = %q", info.PinnedPeerCertSha256)
	}
}

func TestBuildCertInfoFromXboardNilCases(t *testing.T) {
	for _, raw := range []string{
		`{"cert_config":{"mode":"none"}}`,
		`{"cert_config":{"cert_mode":""}}`,
		`{"cert_config":null}`,
		`{}`,
	} {
		var wrap struct {
			CertConfig *XboardCertConfig `json:"cert_config"`
		}
		if err := json.Unmarshal([]byte(raw), &wrap); err != nil {
			t.Fatal(err)
		}
		if info := buildCertInfoFromXboard(wrap.CertConfig, nil); info != nil {
			t.Errorf("%s should give nil CertInfo, got %+v", raw, info)
		}
	}
}

func TestBuildCertInfoFromXboardMapDNSEnv(t *testing.T) {
	raw := `{"cert_config":{"cert_mode":"dns","dns_env":{"CF_TOKEN":"abc"}}}`
	var wrap struct {
		CertConfig *XboardCertConfig `json:"cert_config"`
	}
	if err := json.Unmarshal([]byte(raw), &wrap); err != nil {
		t.Fatal(err)
	}
	info := buildCertInfoFromXboard(wrap.CertConfig, nil)
	if info == nil || info.DNSEnv["CF_TOKEN"] != "abc" {
		t.Fatalf("map dns_env not parsed: %+v", info)
	}
}

// Xboard vless: decryption is a top-level field, not encryption_settings.
func TestVAllssDecryptionField(t *testing.T) {
	raw := `{"server_port":443,"tls":1,"flow":"xtls-rprx-vision","decryption":"aGVsbG8td29ybGQ"}`
	var n VAllssNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatal(err)
	}
	if n.Decryption != "aGVsbG8td29ybGQ" {
		t.Errorf("decryption = %q", n.Decryption)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", n.Flow)
	}
}

// Xboard shadowsocks: plugin fields must at least be parsed so the caller
// can warn, not silently dropped by the JSON decoder.
func TestShadowsocksPluginFields(t *testing.T) {
	raw := `{"server_port":8388,"cipher":"aes-256-gcm","plugin":"v2ray-plugin","plugin_opts":"tls;host=example.com"}`
	var n ShadowsocksNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatal(err)
	}
	if n.Plugin != "v2ray-plugin" || n.PluginOpts != "tls;host=example.com" {
		t.Errorf("plugin = %q opts = %q", n.Plugin, n.PluginOpts)
	}
}

// Xboard hysteria v2 is identified by obfs-password presence in the
// config response; v1 has only obfs.
func TestHysteriaVersionSignal(t *testing.T) {
	v2 := `{"server_port":443,"up_mbps":100,"down_mbps":100,"obfs":"salamander","obfs-password":"secret"}`
	var h2 Hysteria2Node
	if err := json.Unmarshal([]byte(v2), &h2); err != nil {
		t.Fatal(err)
	}
	if h2.ObfsPassword != "secret" || h2.ObfsType != "salamander" {
		t.Errorf("v2 fields = %+v", h2)
	}
	v1 := `{"server_port":443,"up_mbps":100,"down_mbps":100,"obfs":"secret"}`
	var h1 HysteriaNode
	if err := json.Unmarshal([]byte(v1), &h1); err != nil {
		t.Fatal(err)
	}
	if h1.Obfs != "secret" {
		t.Errorf("v1 obfs = %q", h1.Obfs)
	}
}

// End-to-end (httptest) simulation of a cedar2025/Xboard config response:
// top-level cert_config, vless decryption, and a hysteria node that is
// actually v2 despite the local NodeType saying hysteria.
func TestGetNodeInfoXboardShapes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("node_id") {
		case "1": // vless + top-level cert_config
			w.Write([]byte(`{"server_port":443,"tls":1,"tls_settings":{"server_name":"node.example.com"},"flow":"xtls-rprx-vision","decryption":"aGVsbG8td29ybGQ","cert_config":{"mode":"remote","tls_cert":"CERT","tls_key":"KEY"},"base_config":{"push_interval":60,"pull_interval":60}}`))
		case "2": // hysteria panel node, actually v2
			w.Write([]byte(`{"server_port":443,"up_mbps":100,"down_mbps":100,"obfs":"salamander","obfs-password":"secret","base_config":{"push_interval":60,"pull_interval":60}}`))
		case "3": // shadowsocks with plugin
			w.Write([]byte(`{"server_port":8388,"cipher":"aes-256-gcm","plugin":"v2ray-plugin","plugin_opts":"tls;host=example.com","base_config":{"push_interval":60,"pull_interval":60}}`))
		default:
			w.WriteHeader(404)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	newClient := func(nodeID int, nodeType string) *Client {
		c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: nodeID, Key: "test", NodeType: nodeType, Timeout: 5})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// vless: decryption + cert_config must both survive GetNodeInfo.
	n1, err := newClient(1, "vless").GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if n1.VAllss.Decryption != "aGVsbG8td29ybGQ" {
		t.Errorf("vless decryption = %q", n1.VAllss.Decryption)
	}
	if n1.CertInfo == nil || n1.CertInfo.CertMode != "remote" || n1.CertInfo.TlsCert != "CERT" {
		t.Errorf("cert_config not parsed: %+v", n1.CertInfo)
	}

	// hysteria: obfs-password promotes local "hysteria" to hysteria2.
	n2, err := newClient(2, "hysteria").GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if n2.Type != "hysteria2" || n2.Hysteria2 == nil || n2.Hysteria2.ObfsPassword != "secret" {
		t.Errorf("hysteria promotion failed: type=%q hysteria2=%+v", n2.Type, n2.Hysteria2)
	}

	// shadowsocks: plugin must be parsed (caller warns, see GetNodeInfo).
	n3, err := newClient(3, "shadowsocks").GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if n3.Shadowsocks.Plugin != "v2ray-plugin" {
		t.Errorf("ss plugin = %q", n3.Shadowsocks.Plugin)
	}
}

func TestServerPathV2(t *testing.T) {
	v2 := &Client{ApiVersion: 2}
	if got := v2.serverPath("/api/v1/server/UniProxy/user", "/api/v2/server/user"); got != "/api/v2/server/user" {
		t.Errorf("v2 path = %q", got)
	}
	v1 := &Client{ApiVersion: 1}
	if got := v1.serverPath("/api/v1/server/UniProxy/user", "/api/v2/server/user"); got != "/api/v1/server/UniProxy/user" {
		t.Errorf("v1 path = %q", got)
	}
}
