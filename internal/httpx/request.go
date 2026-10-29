package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

const maxBodyBytes = 64 << 10

// DecodeJSON reads a JSON body into v, rejecting oversized bodies and unknown fields.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ClientIP returns the client address. When header is set (for example behind a trusted proxy),
// its first value is used. Only set it when the proxy overwrites that header.
func ClientIP(r *http.Request, header string) string {
	if header != "" {
		if v := strings.TrimSpace(strings.Split(r.Header.Get(header), ",")[0]); v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
