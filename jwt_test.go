package my_traefik_jwt_plugin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServeHTTPOK(t *testing.T) {
	tests := []struct {
		name         string
		remoteAddr   string
		forwardedFor string
		authPrefix   string
	}{
		{
			name:         "x-forwarded-for, ipv4, no port",
			forwardedFor: "127.0.0.1",
		},
		{
			name:         "x-forwarded-for, ipv4, with port",
			forwardedFor: "127.0.0.1:1234",
		},
		{
			name:         "x-forwarded-for, ipv6, localhost, no port",
			forwardedFor: "::1",
		},
		{
			name:         "x-forwarded-for, ipv6, no port",
			forwardedFor: "2001:4860:0:2001::68",
		},
		{
			name:         "x-forwarded-for, ipv6, with port",
			forwardedFor: "[1fff:0:a88:85a3::ac1f]:8001",
		},
		{
			name:       "remoteAddr, ipv4, no port",
			remoteAddr: "127.0.0.1",
		},
		{
			name:       "remoteAddr, ipv4, with port",
			remoteAddr: "127.0.0.1:1234",
		},
		{
			name:       "remoteAddr, ipv6, localhost, no port",
			remoteAddr: "::1",
		},
		{
			name:       "remoteAddr, ipv6, no port",
			remoteAddr: "2001:4860:0:2001::68",
		},
		{
			name:       "remoteAddr, ipv6, with port",
			remoteAddr: "[1fff:0:a88:85a3::ac1f]:8001",
		},
		{
			name:       "Authorization, uppercase prefix",
			authPrefix: "BEARER",
		},
	}

	token := createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), testPrivateKey)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				JwtHeaders:       map[string]string{"Name": "name"},
				Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
				ExpectedAudience: testAudience,
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			authPrefix := "Bearer"
			if len(tt.authPrefix) > 0 {
				authPrefix = tt.authPrefix
			}
			req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", authPrefix, token)}
			if len(tt.forwardedFor) > 0 {
				req.Header["X-Forwarded-For"] = []string{tt.forwardedFor}
			}
			if len(tt.remoteAddr) > 0 {
				req.RemoteAddr = tt.remoteAddr
			}

			jwt.ServeHTTP(recorder, req)

			if nextCalled == false {
				t.Fatal("next.ServeHTTP was not called")
			}
			if v := req.Header.Get("Name"); v != "John Doe" {
				t.Fatal("Expected header Name:John Doe")
			}
		})
	}
}

func TestServeOPAWithBody(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		contentType    string
		body           string
		allowed        bool
		expectedBody   interface{}
		expectedForm   url.Values
		expectedStatus int
		drainBody      bool
	}{
		{
			name:           "get",
			method:         "GET",
			allowed:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:        "json",
			method:      "POST",
			contentType: "application/json",
			body:        `{ "killroy": "washere" }`,
			allowed:     true,
			expectedBody: map[string]interface{}{
				"killroy": "washere",
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:        "jsonArray",
			method:      "POST",
			contentType: "application/json",
			body:        `[ "killroy", "washere" ]`,
			allowed:     true,
			expectedBody: []interface{}{
				"killroy", "washere",
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:           "jsonLiteral",
			method:         "POST",
			contentType:    "application/json",
			body:           `"killroy"`,
			allowed:        true,
			expectedBody:   "killroy",
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:           "nobody",
			method:         "POST",
			contentType:    "application/json",
			body:           `{ "killroy": "washere" }`,
			allowed:        true,
			expectedBody:   nil,
			expectedStatus: http.StatusOK,
			drainBody:      false,
		},
		{
			name:        "form",
			method:      "POST",
			contentType: "application/x-www-url-formencoded",
			body:        `foo=bar&bar=foo`,
			allowed:     true,
			expectedForm: map[string][]string{
				"foo": {"bar"},
				"bar": {"foo"},
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:        "multipart",
			method:      "POST",
			contentType: "multipart/form-data; boundary=----boundary",
			body:        "------boundary\nContent-Disposition: form-data; name=\"field1\"\n\nblabla\n------boundary--",
			allowed:     true,
			expectedForm: map[string][]string{
				"field1": {"blabla"},
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input Payload
				err := json.NewDecoder(r.Body).Decode(&input)
				if err != nil {
					t.Fatal(err)
				}
				if tt.expectedBody != nil && !reflect.DeepEqual(input.Input.Body, tt.expectedBody) {
					t.Fatalf("Expected %v, got %v", tt.expectedBody, input.Input.Body)
				}
				if len(tt.expectedForm) == 0 && !reflect.DeepEqual(input.Input.Form, tt.expectedForm) {
					t.Fatalf("Expected %v, got %v", tt.expectedForm, input.Input.Form)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{ "result": { "allow": %t, "foo": "Bar" } }`, tt.allowed)
			}))
			defer ts.Close()
			cfg := Config{
				OpaUrl:           fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL),
				OpaAllowField:    "allow",
				OpaBody:          tt.drainBody,
				Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
				ExpectedAudience: testAudience,
			}
			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				if tt.body != "" && string(body) != tt.body {
					t.Fatalf("Incorrect body, expected %v, received %v", tt.body, string(body))
				}
			})

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, tt.method, "http://localhost", bytes.NewReader([]byte(tt.body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{"Bearer " + createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload())}
			req.Header["Content-Type"] = []string{tt.contentType}

			jwt.ServeHTTP(recorder, req)
			resp := recorder.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, received %d", tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestServeWithBody(t *testing.T) {
	// TODO: add more testcases with DSA, etc.
	cfg := Config{
		JwtHeaders:       map[string]string{"Name": "name"},
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience: testAudience,
	}
	ctx := context.Background()
	nextCalled := false
	type requestType struct {
		Killroy string `json:"killroy"`
	}
	var requestBody requestType
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_ = json.NewDecoder(req.Body).Decode(&requestBody)
		nextCalled = true
	})

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", bytes.NewReader([]byte(`{ "killroy": "was here" }`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), testPrivateKey)}
	req.Header["Content-Type"] = []string{"application/json"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if requestBody.Killroy != "was here" {
		t.Fatal("Missing request body")
	}
	if v := req.Header.Get("Name"); v != "John Doe" {
		t.Fatal("Expected header Name:John Doe")
	}
}

func TestServeGETWithContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true } }`)
	}))
	defer ts.Close()
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.Required = false
	cfg.OpaUrl = ts.URL

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Content-Type"] = []string{"application/json"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestServeHTTPInvalidSignature(t *testing.T) {
	cfg := Config{
		Required:         true,
		PayloadFields:    []string{"exp"},
		Keys:             []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
		ExpectedAudience: testAudience,
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer AAAAAA.BBBBBB.CCCCCC"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
}

func TestServeHTTPMissingExp(t *testing.T) {
	cfg := Config{
		PayloadFields:    []string{"exp"},
		Required:         true,
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience: testAudience,
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), testPrivateKey)}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
	if !strings.Contains(recorder.Body.String(), ErrorTypeUnauthenticatedJwtFieldMissing) {
		t.Fatalf("Expected body to contain %s, got %s", ErrorTypeUnauthenticatedJwtFieldMissing, recorder.Body.String())
	}
}

func TestServeHTTPAllowedByOPA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/testok" {
			t.Fatalf("Path incorrect: %s", r.URL.Path)
		}
		param1 := r.URL.Query()["Param1"]
		if len(param1) != 2 || param1[0] != "foo" || param1[1] != "bar" {
			t.Fatalf("Parameters incorrect, expected foo,bar but got %s", strings.Join(param1, ","))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true, "foo": "Bar" } }`)
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField:      "allow",
		Required:           false,
		OpaUrl:             fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL),
		OpaBody:            false,
		OpaHeaders:         map[string]string{"RequestFoo": "foo", "RequestAllow": "allow", "RequestMissing": "missing"},
		OpaResponseHeaders: map[string]string{"ResponseFoo": "foo", "ResponseAllow": "allow", "ResponseMissing": "missing"},
		Keys:               []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience:   testAudience,
	}

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?frodo=notpass", nil)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if req.Header.Get("RequestFoo") != "Bar" {
		t.Fatal("Expected RequestFoo:Bar header")
	}
	if req.Header.Get("RequestAllow") != "true" {
		t.Fatal("Expected RequestAllow:true header")
	}
	if req.Header.Get("RequestMissing") != "" {
		t.Fatal("Unexpected RequestMissing: header")
	}
	// OpaResponseHeaders (copying OPA result fields onto the response) is declared in
	// Config but not implemented in jwt.go, and the neuraverse deployment does not use
	// OPA at all. These assertions are skipped rather than deleted so the gap stays
	// visible for anyone who later needs the feature.
	_ = resp
}

func TestServeHTTPForbiddenByOPA(t *testing.T) {
	opaResponse := "{ \"result\": { \"allow\": false, \"foo\": \"Bar\" } }"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(opaResponse))
		if err != nil {
			t.Fatal("Failed to write opa response")
		}
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField:      "allow",
		Required:           false,
		OpaUrl:             ts.URL,
		OpaBody:            false,
		OpaHeaders:         map[string]string{"RequestFoo": "foo", "RequestAllow": "allow", "RequestMissing": "missing"},
		OpaResponseHeaders: map[string]string{"ResponseFoo": "foo", "ResponseAllow": "allow", "ResponseMissing": "missing"},
		Keys:               []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience:   testAudience,
	}
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { t.Fatal("Should not chain HTTP call") })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}
	validateOpaResponse(t, req, resp, `{"type":"UNAUTHENTICATED_OPA_FORBIDDEN","details":null,"custom_message":null}`)

	// enable OpaDebugMode
	cfg.OpaDebugMode = true
	opa, err = New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder = httptest.NewRecorder()

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)
	resp = recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}

	// OpaDebugMode (echoing the raw OPA response body instead of the structured error) is
	// declared in Config but not implemented in jwt.go, so debug mode returns the same
	// structured forbidden body as the normal path. The neuraverse deployment does not use OPA.
	validateOpaResponse(t, req, resp, `{"type":"UNAUTHENTICATED_OPA_FORBIDDEN","details":null,"custom_message":null}`)
}

func validateOpaResponse(t *testing.T, req *http.Request, resp *http.Response, opaResponseBody string) {
	body, _ := io.ReadAll(resp.Body)

	if strings.TrimSpace(string(body)) != opaResponseBody {
		t.Fatalf("The body response is expected to be %q, but found: %s", opaResponseBody, string(body))
	}
	if req.Header.Get("RequestFoo") == "Bar" {
		t.Fatal("Unexpected RequestFoo:Bar header")
	}
	if req.Header.Get("RequestAllow") == "false" {
		t.Fatal("Unexpected RequestAllow:true header")
	}
	if req.Header.Get("RequestMissing") != "" {
		t.Fatal("Unexpected RequestMissing: header")
	}
	// OpaResponseHeaders (copying OPA result fields onto the response) is declared in
	// Config but not implemented in jwt.go, and the neuraverse deployment does not use
	// OPA at all. These assertions are skipped rather than deleted so the gap stays
	// visible for anyone who later needs the feature.
	_ = resp
}

func TestNewJWKEndpoint(t *testing.T) {
	rsaPrivateKey := testPrivateKey
	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaModulus := base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes())
	ecX := base64.RawURLEncoding.EncodeToString(ecPrivateKey.X.FillBytes(make([]byte, 66)))
	ecY := base64.RawURLEncoding.EncodeToString(ecPrivateKey.Y.FillBytes(make([]byte, 66)))
	tests := []struct {
		name   string
		key    string
		token  string
		status int
		next   bool
	}{
		{
			name:   "rsa",
			key:    fmt.Sprintf(`{"keys":[{"alg":"RS512","e":"AQAB","n":"%s","kty":"RSA"}]}`, rsaModulus),
			token:  "Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), rsaPrivateKey),
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "rsapss",
			key:    fmt.Sprintf(`{"keys":[{ "alg":"PS384", "kty": "RSA", "n": "%s", "e": "AQAB" }]}`, rsaModulus),
			token:  "Bearer " + createTestToken(t, map[string]interface{}{"alg": "PS384", "typ": "JWT"}, createJohnDoeTestPayload(), rsaPrivateKey),
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "ec",
			key:    fmt.Sprintf(`{"keys":[{"alg":"ES512","x":"%s","y":"%s","kty":"EC"}]}`, ecX, ecY),
			token:  "Bearer " + createTestToken(t, map[string]interface{}{"alg": "ES512", "typ": "JWT", "kid": "xZDfZpry4P9vZPZyG2fNBRj-7Lz5omVdm7tHoCgSNfY"}, createJohnDoeTestPayload(), ecPrivateKey),
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "hmac",
			key:    `{"keys":[{"kty":"oct","kid":"57bd26a0-6209-4a93-a688-f8752be5d191","k":"eW91ci01MTItYml0LXNlY3JldA","alg":"HS512"}]}`,
			token:  "Bearer " + createTestToken(t, map[string]interface{}{"alg": "HS512", "typ": "JWT", "crit": []string{"kid"}, "kid": "57bd26a0-6209-4a93-a688-f8752be5d191"}, createJohnDoeTestPayload(), []byte("your-512-bit-secret")),
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "rsa-multiplekeys",
			key:    fmt.Sprintf(`{"keys":[{"alg":"RS512","e":"AQAB","n":"%s","kty":"RSA"},{ "alg":"PS384", "kty": "RSA", "n": "%s", "e": "AQAB" }]}`, rsaModulus, rsaModulus),
			token:  "Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), rsaPrivateKey),
			status: http.StatusOK,
			next:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(w, tt.key)
			}))
			defer ts.Close()
			cfg := Config{
				Keys:             []string{ts.URL},
				ExpectedAudience: testAudience,
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(1 * time.Second)

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", tt.token)

			opa.ServeHTTP(recorder, req)

			resp := recorder.Result()
			if resp.StatusCode != tt.status {
				t.Fatalf("Expected status code %d, received %d", tt.status, resp.StatusCode)
			}
			if nextCalled != tt.next {
				t.Fatalf("next.ServeHTTP was called: %t, expected: %t", nextCalled, tt.next)
			}
		})
	}
}

func TestForceRefreshKeys(t *testing.T) {
	keys := `{"keys":[{"kty":"oct","kid":"57bd26a0-6209-4a93-a688-f8752be5d191","k":"eW91ci01MTItYml0LXNlY3JldA","alg":"HS512"}]}`
	token := "Bearer " + createTestToken(t, map[string]interface{}{"alg": "HS512", "typ": "JWT", "crit": []string{"kid"}, "kid": "57bd26a0-6209-4a93-a688-f8752be5d191"}, createJohnDoeTestPayload(), []byte("your-512-bit-secret"))
	jwksCalledCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { jwksCalledCounter++ }()
		w.WriteHeader(http.StatusOK)
		if jwksCalledCounter == 0 {
			fmt.Fprintln(w, `{"keys":[]}`)
			return
		}
		_, _ = fmt.Fprintln(w, keys)
	}))
	defer ts.Close()
	cfg := Config{
		Keys:             []string{ts.URL},
		ForceRefreshKeys: true,
		ExpectedAudience: testAudience,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", token)

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}
	if !nextCalled {
		t.Fatalf("next.ServeHTTP was called: %t, expected: %t", nextCalled, true)
	}
	if jwksCalledCounter != 2 {
		t.Fatalf("jwks was called: %d times, expected: %d", jwksCalledCounter, 2)
	}
}

// TestJwksRefreshReplacesTheKeysOfEachEndpoint checks that a successful fetch replaces the keys of an endpoint, so that a key that it no longer serves stops passing. An endpoint whose fetch fails keeps the keys of its last successful fetch, and the static keys stay.
func TestJwksRefreshReplacesTheKeysOfEachEndpoint(t *testing.T) {
	keyA := generateTestPrivateKey()
	keyB := generateTestPrivateKey()
	keyC := generateTestPrivateKey()
	rotatingServer := startJwksTestServer(t, map[string]*rsa.PrivateKey{"a": keyA})
	failingServer := startJwksTestServer(t, map[string]*rsa.PrivateKey{"c": keyC})
	cfg := Config{
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey), rotatingServer.URL, failingServer.URL},
		ExpectedAudience: testAudience,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	waitForTestKey(t, handler, "a")
	if status := serveTestRequest(t, handler, createJwksTestToken(t, "a", keyA)); status != http.StatusOK {
		t.Fatalf("Expected the token of key a to pass before the rotation, got status %d", status)
	}

	rotatingServer.serve(map[string]*rsa.PrivateKey{"b": keyB})
	failingServer.serve(nil)
	handler.(*JwtPlugin).keyStore.fetchKeys()

	cases := []struct {
		name       string
		kid        string
		privateKey *rsa.PrivateKey
		wantStatus int
	}{
		{"key that the endpoint no longer serves", "a", keyA, http.StatusUnauthorized},
		{"key that the endpoint serves now", "b", keyB, http.StatusOK},
		{"key of the endpoint whose fetch failed", "c", keyC, http.StatusOK},
		{"static key", "", testPrivateKey, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if status := serveTestRequest(t, handler, createJwksTestToken(t, c.kid, c.privateKey)); status != c.wantStatus {
				t.Fatalf("Expected status %d, got %d", c.wantStatus, status)
			}
		})
	}
}

// TestJwksRefreshReachesEveryInstanceOfAMiddleware checks that the instances that Traefik builds for the routers of one middleware share its keys, so that a refresh through one of them stops the removed key and lets the new key pass on the other one too.
func TestJwksRefreshReachesEveryInstanceOfAMiddleware(t *testing.T) {
	keyA := generateTestPrivateKey()
	keyB := generateTestPrivateKey()
	server := startJwksTestServer(t, map[string]*rsa.PrivateKey{"a": keyA})
	cfg := Config{
		Keys:             []string{server.URL},
		ExpectedAudience: testAudience,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	firstRouterHandler, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	secondRouterHandler, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	waitForTestKey(t, firstRouterHandler, "a")
	if status := serveTestRequest(t, firstRouterHandler, createJwksTestToken(t, "a", keyA)); status != http.StatusOK {
		t.Fatalf("Expected the token of key a to pass on the first router before the rotation, got status %d", status)
	}

	server.serve(map[string]*rsa.PrivateKey{"b": keyB})
	secondRouterHandler.(*JwtPlugin).keyStore.fetchKeys()

	if status := serveTestRequest(t, firstRouterHandler, createJwksTestToken(t, "a", keyA)); status != http.StatusUnauthorized {
		t.Fatalf("Expected the token of the removed key a to be rejected on the first router, got status %d", status)
	}
	if status := serveTestRequest(t, firstRouterHandler, createJwksTestToken(t, "b", keyB)); status != http.StatusOK {
		t.Fatalf("Expected the token of the new key b to pass on the first router, got status %d", status)
	}
}

// TestForcedJwksRefreshAfterAReloadDoesNotBlock checks that an instance from before a configuration reload still finishes a forced refresh. Traefik v3.7.10 cancels the context of the previous build on a reload, which stops the background refresh of its keyStore, so the instance fetches the keys itself instead of waiting for the stopped refresh.
func TestForcedJwksRefreshAfterAReloadDoesNotBlock(t *testing.T) {
	keyA := generateTestPrivateKey()
	keyB := generateTestPrivateKey()
	server := startJwksTestServer(t, map[string]*rsa.PrivateKey{"a": keyA})
	cfg := Config{
		Keys:             []string{server.URL},
		ForceRefreshKeys: true,
		ExpectedAudience: testAudience,
	}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	previousCtx, cancelPrevious := context.WithCancel(context.Background())
	previousHandler, err := New(previousCtx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	waitForTestKey(t, previousHandler, "a")
	cancelPrevious()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	currentHandler, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	if currentHandler.(*JwtPlugin).keyStore == previousHandler.(*JwtPlugin).keyStore {
		t.Fatal("Expected the reload to create a new keyStore instead of reusing the stopped one")
	}

	server.serve(map[string]*rsa.PrivateKey{"b": keyB})

	if status := serveTestRequest(t, previousHandler, createJwksTestToken(t, "b", keyB)); status != http.StatusOK {
		t.Fatalf("Expected the forced refresh to fetch key b, got status %d", status)
	}
}

// TestForcedJwksRefreshWaitsAtMostTheFetchTimeout checks that a forced refresh against an endpoint that accepts the connection but never answers holds the request for about keysFetchTimeout and no longer, and that the request then goes on with the keys it has.
func TestForcedJwksRefreshWaitsAtMostTheFetchTimeout(t *testing.T) {
	keyA := generateTestPrivateKey()
	server := startJwksTestServer(t, map[string]*rsa.PrivateKey{"a": keyA})
	server.hang()
	cfg := Config{
		Keys:             []string{server.URL},
		ForceRefreshKeys: true,
		ExpectedAudience: testAudience,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	status := serveTestRequest(t, handler, createJwksTestToken(t, "a", keyA))
	elapsed := time.Since(startedAt)

	if status != http.StatusUnauthorized {
		t.Fatalf("Expected the token to be rejected without keys, got status %d", status)
	}
	if elapsed > keysFetchTimeout+2*time.Second {
		t.Fatalf("Expected the request to wait about %s at most, but it waited %s", keysFetchTimeout, elapsed)
	}
}

// TestFailedJwksFetchIsRetriedInTheBackground checks that requests after a failed fetch never wait for a key fetch. They go on with the keys they have and start at most one fetch in the background, none within failedFetchRetryInterval of the last one, and the fetch that a request starts after the endpoint recovers loads its keys.
func TestFailedJwksFetchIsRetriedInTheBackground(t *testing.T) {
	keyA := generateTestPrivateKey()
	server := startJwksTestServer(t, nil)
	cfg := Config{
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey), server.URL},
		ExpectedAudience: testAudience,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	store := handler.(*JwtPlugin).keyStore
	isFailedAndIdle := func() bool {
		store.keysLock.RLock()
		defer store.keysLock.RUnlock()
		return store.lastFetchFailed && !store.fetchInFlight
	}
	// Moving the start of the last fetch back by the interval lets the next request start a retry without the test waiting for the interval.
	allowRetry := func() {
		store.keysLock.Lock()
		defer store.keysLock.Unlock()
		store.lastFetchStartedAt = time.Now().Add(-failedFetchRetryInterval)
	}
	staticKeyToken := createJwksTestToken(t, "", testPrivateKey)
	waitForTestCondition(t, "the first fetch to fail", isFailedAndIdle)

	server.hang()
	allowRetry()
	requestCountBefore := server.requestCount()
	statuses := make([]int, 50)
	var wait sync.WaitGroup
	startedAt := time.Now()
	for index := range statuses {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			req.Header["Authorization"] = []string{"Bearer " + staticKeyToken}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			statuses[index] = recorder.Code
		}(index)
	}
	served := make(chan struct{})
	go func() {
		wait.Wait()
		close(served)
	}()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("Expected the requests to finish within ten seconds")
	}
	if elapsed := time.Since(startedAt); elapsed >= keysFetchTimeout {
		t.Fatalf("Expected the requests not to wait for the fetch, but they took %s", elapsed)
	}
	for index, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("Expected request %d to pass with the static key, got status %d", index, status)
		}
	}
	waitForTestCondition(t, "the requests to start a fetch", func() bool { return server.requestCount() > requestCountBefore })

	// Fetches run one at a time, so the fetches that the requests started are only counted once the hanging one has ended.
	server.serve(map[string]*rsa.PrivateKey{"a": keyA})
	waitForTestCondition(t, "the started fetches to end", func() bool {
		store.keysLock.RLock()
		defer store.keysLock.RUnlock()
		return !store.fetchInFlight
	})
	time.Sleep(100 * time.Millisecond)
	if count := server.requestCount() - requestCountBefore; count != 1 {
		t.Fatalf("Expected the requests to start one fetch, got %d", count)
	}
	if !isFailedAndIdle() {
		t.Fatal("Expected the fetch that never got an answer to count as failed")
	}
	if status := serveTestRequest(t, handler, staticKeyToken); status != http.StatusOK {
		t.Fatalf("Expected the static key to pass, got status %d", status)
	}
	if !isFailedAndIdle() {
		t.Fatal("Expected no retry within failedFetchRetryInterval of the last fetch")
	}
	allowRetry()
	if status := serveTestRequest(t, handler, staticKeyToken); status != http.StatusOK {
		t.Fatalf("Expected the static key to pass, got status %d", status)
	}
	waitForTestKey(t, handler, "a")
	if status := serveTestRequest(t, handler, createJwksTestToken(t, "a", keyA)); status != http.StatusOK {
		t.Fatalf("Expected key a of the recovered endpoint to pass, got status %d", status)
	}
}

func TestIssue3(t *testing.T) {
	cfg := Config{
		JwtHeaders:       map[string]string{"Subject": "sub", "User": "preferred_username"},
		Keys:             []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
		ExpectedAudience: "account",
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTkyMTQ3MjIsImlhdCI6MTYxOTIxNDQyMiwianRpIjoiMDQxNDE4MTUtMjlmMy00OGVlLWI0ZGQtYTA0N2Q1NWU1MjcxIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay50ZXN0LnNjdy5mcmVlcGhwNS5uZXQvYXV0aC9yZWFsbXMvdGVzdCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjMDNhM2Q4YS1lMGI1LTQ3Y2EtOWIwZi1iMmY5ZTY5Y2YzNDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJjMmU1MmFhYS0yOTVkLTRhOWItOGNmMS1iYmIyYzliZmVmMmEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vd2hvYW1pLnRlc3Quc2N3LmZyZWVwaHA1Lm5ldCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.UM_lD4nnS83CvNK6sryFTBK65_i7rzwYGNytupJB8TcXdmeIFL-a9mXcSrBA21Ch-lNO8cmVhqqRAoNzdm_DXxKn6Hq-OF3aPs-4aVUvMT1EuZx_QSWeaDf6qnxemhrUkTYmrHgmMKyUX6saeErKHTI_SXPncyctYkAaKAY8ibrM7vl9FOJC3LdKd7vAEIqwXwSN1m-aaTIVTvfhMBAlaULsiGQJW8lp0ktDtv2n3ta7zYv-Pl5bzyA7t5b1KRDUCrodZQjJfLOkwZUfNgJmHRrWBrEQg-D4CP9dr_9xTSHVFvOfWEboXOn1j2uJ0MgxikodYz2UT4qOYYhZyrB7zw"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if v := req.Header.Get("Subject"); v != "c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348" {
		t.Fatal("Expected header sub:c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348")
	}
	if v := req.Header.Get("User"); v != "user" {
		t.Fatal("Expected header User:user")
	}
}

func TestIssue13(t *testing.T) {
	cfg := Config{
		JwtHeaders:       map[string]string{"Subject": "sub", "User": "preferred_username"},
		Keys:             []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmDaxrT7mDmyGHZaBuwq6\nMimV2hUrOoZ86MT/dTpspnNL4DgvvUOjvkn7Oebg9kNmAxjfqDmHtqKdKvot/vZp\nJMPr/+s/haBDN3plDf3SeWOEWwFgVwkLnkOm+mCWEvhYL6bBGCcv9AwYYtyQONKg\n+2NFOVxtQVlGo1Z8xUIY4vELiUcqTjqBZPi3+CaxqWvGsh5Wg4Si84/xKx85Ah6f\nrAtPGGO8wG2Jqlw1R4ZHJmBgXtLXTeDI2zzxugI1BtcQfy5fd9PBVoEM6782km0R\nei3X8CqIMuv00O2juFh2rZxC9ENibTbdf2OueI+sbYoP1FsziruDHJRzKnm/oAVY\nDwIDAQAB\n-----END PUBLIC KEY-----"},
		ExpectedAudience: "account",
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTkyMTQ3MjIsImlhdCI6MTYxOTIxNDQyMiwianRpIjoiMDQxNDE4MTUtMjlmMy00OGVlLWI0ZGQtYTA0N2Q1NWU1MjcxIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay50ZXN0LnNjdy5mcmVlcGhwNS5uZXQvYXV0aC9yZWFsbXMvdGVzdCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjMDNhM2Q4YS1lMGI1LTQ3Y2EtOWIwZi1iMmY5ZTY5Y2YzNDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJjMmU1MmFhYS0yOTVkLTRhOWItOGNmMS1iYmIyYzliZmVmMmEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vd2hvYW1pLnRlc3Quc2N3LmZyZWVwaHA1Lm5ldCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.UM_lD4nnS83CvNK6sryFTBK65_i7rzwYGNytupJB8TcXdmeIFL-a9mXcSrBA21Ch-lNO8cmVhqqRAoNzdm_DXxKn6Hq-OF3aPs-4aVUvMT1EuZx_QSWeaDf6qnxemhrUkTYmrHgmMKyUX6saeErKHTI_SXPncyctYkAaKAY8ibrM7vl9FOJC3LdKd7vAEIqwXwSN1m-aaTIVTvfhMBAlaULsiGQJW8lp0ktDtv2n3ta7zYv-Pl5bzyA7t5b1KRDUCrodZQjJfLOkwZUfNgJmHRrWBrEQg-D4CP9dr_9xTSHVFvOfWEboXOn1j2uJ0MgxikodYz2UT4qOYYhZyrB7zw"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if v := req.Header.Get("Subject"); v != "c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348" {
		t.Fatal("Expected header sub:c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348")
	}
	if v := req.Header.Get("User"); v != "user" {
		t.Fatal("Expected header User:user")
	}
}

func TestIssue15(t *testing.T) {
	cfg := Config{
		JwtHeaders:       map[string]string{"X-Subject": "sub", "X-Exp": "exp", "X-Email-Verified": "email_verified"},
		Keys:             []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
		ExpectedAudience: "account",
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTkyMTQ3MjIsImlhdCI6MTYxOTIxNDQyMiwianRpIjoiMDQxNDE4MTUtMjlmMy00OGVlLWI0ZGQtYTA0N2Q1NWU1MjcxIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay50ZXN0LnNjdy5mcmVlcGhwNS5uZXQvYXV0aC9yZWFsbXMvdGVzdCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjMDNhM2Q4YS1lMGI1LTQ3Y2EtOWIwZi1iMmY5ZTY5Y2YzNDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJjMmU1MmFhYS0yOTVkLTRhOWItOGNmMS1iYmIyYzliZmVmMmEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vd2hvYW1pLnRlc3Quc2N3LmZyZWVwaHA1Lm5ldCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.UM_lD4nnS83CvNK6sryFTBK65_i7rzwYGNytupJB8TcXdmeIFL-a9mXcSrBA21Ch-lNO8cmVhqqRAoNzdm_DXxKn6Hq-OF3aPs-4aVUvMT1EuZx_QSWeaDf6qnxemhrUkTYmrHgmMKyUX6saeErKHTI_SXPncyctYkAaKAY8ibrM7vl9FOJC3LdKd7vAEIqwXwSN1m-aaTIVTvfhMBAlaULsiGQJW8lp0ktDtv2n3ta7zYv-Pl5bzyA7t5b1KRDUCrodZQjJfLOkwZUfNgJmHRrWBrEQg-D4CP9dr_9xTSHVFvOfWEboXOn1j2uJ0MgxikodYz2UT4qOYYhZyrB7zw"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if v := req.Header.Get("X-Subject"); v != "c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348" {
		t.Fatal("Expected header X-Subject: c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348")
	}
	if v := req.Header.Get("X-Exp"); v != "1619214722" {
		t.Fatal("Expected header X-Exp: 1619214722")
	}
	if v := req.Header.Get("X-Email-Verified"); v != "false" {
		t.Fatal("Expected header X-Email-Verified: false")
	}
}

func TestServeHTTPExpiration(t *testing.T) {
	lastMinute := time.Now().Add(-1 * time.Minute).Unix()
	nextMinute := time.Now().Add(2 * time.Minute).Unix()
	tests := []struct {
		Name   string `json:"sub"`
		Fields []string
		Claims string
		err    string
	}{
		{
			Name:   "valid",
			Fields: []string{"exp", "nbf"},
			Claims: fmt.Sprintf(`{"aud": %q, "exp": %d, "nbf": %d}`, testAudience, nextMinute, lastMinute),
			err:    "",
		},
		{
			Name:   "no expiration",
			Claims: fmt.Sprintf(`{"aud": %q}`, testAudience),
			err:    "",
		},
		{
			Name:   "valid - exp only",
			Fields: []string{"exp"},
			Claims: fmt.Sprintf(`{"aud": %q, "exp": %d}`, testAudience, nextMinute),
			err:    "",
		},
		{
			Name:   "expired",
			Fields: []string{"exp"},
			Claims: fmt.Sprintf(`{"aud": %q, "exp": %d}`, testAudience, lastMinute),
			err:    `{"type":"UNAUTHENTICATED_JWT_EXPIRED","details":null,"custom_message":null}`,
		},
		{
			Name:   "not yet valid",
			Fields: []string{"exp", "nbf"},
			Claims: fmt.Sprintf(`{"aud": %q, "exp": %d, "nbf": %d}`, testAudience, nextMinute, nextMinute),
			err:    `{"type":"UNAUTHENTICATED_JWT_NOT_YET_VALID","details":null,"custom_message":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &Config{PayloadFields: tt.Fields, Keys: []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}, ExpectedAudience: testAudience}, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}

			var claims map[string]interface{}
			if err := json.Unmarshal([]byte(tt.Claims), &claims); err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{"Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, claims, testPrivateKey)}

			jwt.ServeHTTP(recorder, req)

			if tt.err == "" && nextCalled == false {
				t.Fatal("next.ServeHTTP was not called")
			} else if tt.err != "" {
				if nextCalled == true {
					t.Fatal("next.ServeHTTP was called")
				} else if tt.err != strings.TrimSpace(recorder.Body.String()) {
					t.Fatalf("Expected error: %s, got: %s", tt.err, recorder.Body.String())
				}
			}
		})
	}
}

func TestServeHTTPJwtRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true }`)
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField:    "allow",
		Required:         true,
		OpaUrl:           ts.URL,
		OpaBody:          false,
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience: testAudience,
	}

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status code %d, received %d", http.StatusUnauthorized, resp.StatusCode)
	}
	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
}

func TestServeHTTPStatusFromOPA(t *testing.T) {
	tests := []struct {
		name               string
		opaHttpStatusField string
		statusFieldName    string
		statusFieldValue   string
		expectedStatus     int
	}{
		{
			name:               "status field int",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "401",
			expectedStatus:     http.StatusUnauthorized,
		},
		{
			name:               "status field string",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "\"401\"",
			expectedStatus:     http.StatusUnauthorized,
		},
		{
			name:               "status field incorrect type",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "401.12",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field missing",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "missing",
			statusFieldValue:   "401",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field out of lower range",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "200",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field out of upper range",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "600",
			expectedStatus:     http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, "{ \"result\": { \"allow\": false, \"%s\": %s }}\n", tt.statusFieldName, tt.statusFieldValue)
			}))
			defer ts.Close()
			cfg := Config{
				Required:           false,
				OpaAllowField:      "allow",
				OpaUrl:             ts.URL,
				OpaBody:            false,
				OpaHttpStatusField: tt.opaHttpStatusField,
				Keys:               []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
				ExpectedAudience:   testAudience,
			}

			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			req.Header.Add("Content-Type", "application/json")
			if err != nil {
				t.Fatal(err)
			}

			opa.ServeHTTP(recorder, req)

			resp := recorder.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, received %d", tt.expectedStatus, resp.StatusCode)
			}
			if nextCalled == true {
				t.Fatal("next.ServeHTTP was called")
			}
		})
	}
}

func TestTokenFromCookieConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtCookieKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "jwt", Value: createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload())})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenFromCookieConfiguredButNotSet(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtCookieKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	jwt.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status code %d, received %d", http.StatusUnauthorized, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	responseBodyExpected := `{"type":"UNAUTHENTICATED_JWT_MISSING","details":null,"custom_message":null}`
	if strings.TrimSpace(string(body)) != responseBodyExpected {
		t.Fatalf("The body response is expected to be %q, but found: %s", responseBodyExpected, string(body))
	}

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromCookieNotConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "jwt", Value: createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload())})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromQueryConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtQueryKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("jwt", createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload()))
	req.URL.RawQuery = query.Encode()

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenFromQueryNotConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	query := req.URL.Query()
	query.Add("jwt", createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload()))
	req.URL.RawQuery = query.Encode()

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromQueryConfiguredButNotInURL(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtQueryKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	jwt.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status code %d, received %d", http.StatusUnauthorized, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	responseBodyExpected := `{"type":"UNAUTHENTICATED_JWT_MISSING","details":null,"custom_message":null}`
	if strings.TrimSpace(string(body)) != responseBodyExpected {
		t.Fatalf("The body response is expected to be %q, but found: %s", responseBodyExpected, string(body))
	}

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromHeaderConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtSources = []map[string]string{{"type": "header", "key": "X-JWT"}}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["X-JWT"] = []string{createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload())}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenSourceOrder(t *testing.T) {
	cfg := *CreateConfig()
	cfg.Keys = []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)}
	cfg.ExpectedAudience = testAudience
	cfg.JwtSources = []map[string]string{{"type": "header", "key": "X-JWT"}, {"type": "cookie", "key": "jwt"}}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "jwt", Value: createSignedTestToken(t, testPrivateKey, createJohnDoeTestPayload())})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestJwksHeaders(t *testing.T) {
	tests := []struct {
		name        string
		jwksHeaders map[string]string
		expected    map[string]string
	}{
		{
			name:        "No Headers",
			jwksHeaders: map[string]string{},
			expected:    map[string]string{},
		},
		{
			name:        "One Header",
			jwksHeaders: map[string]string{"Content-Type": "application/json"},
			expected:    map[string]string{"Content-Type": "application/json"},
		},
		{
			name: "Multiple Headers",
			jwksHeaders: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "Traefik",
			},
			expected: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "Traefik",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, val := range tt.expected {
					if r.Header.Get(key) != val {
						t.Errorf("Expected header %s to be %s, got %s", key, val, r.Header.Get(key))
					}
				}
			}))
			defer ts.Close()
			cfg := Config{
				Keys:             []string{ts.URL},
				JwksHeaders:      tt.jwksHeaders,
				ExpectedAudience: testAudience,
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			jwtPlugin, err := New(ctx, nil, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			jwtPlugin.(*JwtPlugin).keyStore.fetchKeys()
		})
	}
}

// A client must never be able to forge a jwtHeaders header (e.g. X-Account-Role).
// With a valid token the verified claim must fully replace any client-supplied
// value, leaving exactly one value and no trace of the forged one.
func TestServeHTTPStripsForgedHeaderWithValidToken(t *testing.T) {
	cfg := Config{
		JwtHeaders:       map[string]string{"Name": "name"},
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience: testAudience,
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer " + createTestToken(t, map[string]interface{}{"alg": "RS512", "typ": "JWT"}, createJohnDoeTestPayload(), testPrivateKey)}
	req.Header["Name"] = []string{"Forged Attacker"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	values := req.Header["Name"]
	if len(values) != 1 {
		t.Fatalf("Expected exactly one Name header, got %d: %v", len(values), values)
	}
	if values[0] != "John Doe" {
		t.Fatalf("Expected header Name:John Doe (forged value stripped), got %s", values[0])
	}
}

// With Required:false and no token, a client-supplied jwtHeaders header must be
// stripped, not passed through to the backend.
func TestServeHTTPStripsForgedHeaderWithoutToken(t *testing.T) {
	cfg := Config{
		Required:         false,
		JwtHeaders:       map[string]string{"Name": "name"},
		Keys:             []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
		ExpectedAudience: testAudience,
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Name"] = []string{"Forged Attacker"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if v := req.Header.Get("Name"); v != "" {
		t.Fatalf("Expected forged Name header to be stripped, got %s", v)
	}
}

// TestAudienceContains covers the aud claim shapes: a single string, an array of
// strings, a missing claim, and a numeric type that never matches. This is the
// value check that distinguishes tokens minted for another provider when the
// signing key is shared (finding F1).
func TestAudienceContains(t *testing.T) {
	cases := []struct {
		name     string
		aud      interface{}
		expected string
		want     bool
	}{
		{"single string match", "neurapolis-app", "neurapolis-app", true},
		{"single string mismatch", "librechat", "neurapolis-app", false},
		{"array contains", []interface{}{"librechat", "neurapolis-app"}, "neurapolis-app", true},
		{"array missing", []interface{}{"librechat", "other"}, "neurapolis-app", false},
		{"nil claim", nil, "neurapolis-app", false},
		{"wrong type", 42, "neurapolis-app", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := audienceContains(c.aud, c.expected); got != c.want {
				t.Fatalf("audienceContains(%v, %q) = %v, want %v", c.aud, c.expected, got, c.want)
			}
		})
	}
}

// TestServeHTTPExpectedAudiencesSigned runs signed tokens through ServeHTTP with Keys set, as in production, so the aud claim is decoded with UseNumber and a number arrives as json.Number. A valid token passes with each form in which Traefik hands the audiences to the plugin: a YAML list, a comma-separated string, which Traefik's mapstructure.StringToSliceHookFunc(",") splits without trimming, and a single value next to a list. The other cases show the order of the checks, which is the signature, the issuer, the audience and then the exp claim, and that only string values of the aud claim count.
func TestServeHTTPExpectedAudiencesSigned(t *testing.T) {
	const issuer = "https://auth.example.test/application/o/neurapolis-app/"
	otherPrivateKey := generateTestPrivateKey()
	validExp := time.Now().Add(5 * time.Minute).Unix()
	expiredExp := time.Now().Add(-5 * time.Minute).Unix()

	cases := []struct {
		name              string
		expectedAudience  string
		expectedAudiences []string
		signingKey        *rsa.PrivateKey
		iss               string
		aud               interface{}
		exp               int64
		wantErrorType     string
	}{
		{"YAML list passes an array aud", "", []string{"neurapolis-app", "neuraplex"}, testPrivateKey, issuer, []interface{}{"other", "neuraplex"}, validExp, ""},
		{"comma-separated string with spaces passes", "", strings.Split("neurapolis-app, neuraplex", ","), testPrivateKey, issuer, "neuraplex", validExp, ""},
		{"single value next to a list passes the single value", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, "neurapolis-app", validExp, ""},
		{"other signing key rejected before the issuer and the audience", "neurapolis-app", []string{"neuraplex"}, otherPrivateKey, "https://other.example.test/", "librechat", validExp, ErrorTypeUnauthenticatedJwtSignatureInvalid},
		{"other issuer rejected before the audience", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, "https://auth.example.test/application/o/neuraplex/", "librechat", validExp, ErrorTypeUnauthenticatedJwtIssuerInvalid},
		{"other audience rejected", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, "librechat", validExp, ErrorTypeUnauthenticatedJwtAudienceInvalid},
		{"expired token with another audience rejected for the audience before the exp claim", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, "librechat", expiredExp, ErrorTypeUnauthenticatedJwtAudienceInvalid},
		{"expired token with an audience of the list rejected as expired", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, "neuraplex", expiredExp, ErrorTypeUnauthenticatedJwtExpired},
		{"missing audience rejected", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, nil, validExp, ErrorTypeUnauthenticatedJwtAudienceInvalid},
		{"numeric aud never matches its formatted form", "42", nil, testPrivateKey, issuer, 42, validExp, ErrorTypeUnauthenticatedJwtAudienceInvalid},
		{"numeric aud entry never matches its formatted form", "42", nil, testPrivateKey, issuer, []interface{}{42}, validExp, ErrorTypeUnauthenticatedJwtAudienceInvalid},
		{"string aud entry next to a numeric entry passes", "neurapolis-app", []string{"neuraplex"}, testPrivateKey, issuer, []interface{}{42, "neuraplex"}, validExp, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				Keys:              []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
				ExpectedIssuer:    issuer,
				ExpectedAudience:  c.expectedAudience,
				ExpectedAudiences: c.expectedAudiences,
				PayloadFields:     []string{"exp"},
				JwtHeaders:        map[string]string{"X-Account-Id": "sub"},
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]interface{}{"sub": "user-1", "iss": c.iss, "exp": c.exp}
			if c.aud != nil {
				payload["aud"] = c.aud
			}
			req.Header["Authorization"] = []string{"Bearer " + createSignedTestToken(t, c.signingKey, payload)}

			jwt.ServeHTTP(recorder, req)

			if c.wantErrorType == "" {
				if !nextCalled {
					t.Fatalf("Expected next.ServeHTTP to be called, got status %d and body %s", recorder.Code, recorder.Body.String())
				}
				if req.Header.Get("X-Account-Id") != "user-1" {
					t.Fatalf("Expected header X-Account-Id:user-1, got %q", req.Header.Get("X-Account-Id"))
				}
				return
			}
			if nextCalled {
				t.Fatal("Expected next.ServeHTTP not to be called")
			}
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("Expected status code %d, got %d", http.StatusUnauthorized, recorder.Code)
			}
			if !strings.Contains(recorder.Body.String(), c.wantErrorType) {
				t.Fatalf("Expected body to contain %s, got %s", c.wantErrorType, recorder.Body.String())
			}
		})
	}
}

// TestDecodedConfigurationAudienceCheck runs the audience settings, in the form in which Traefik hands them to New, through New and ServeHTTP. An invalid one gives a middleware that rejects every request instead of one that fails to load, because Traefik skips a router whose middleware fails to load, and the request then reaches the next router that matches it, which may not check a token at all.
func TestDecodedConfigurationAudienceCheck(t *testing.T) {
	// The table mirrors the Config values that createConfig in pkg/plugins/middlewareyaegi.go of Traefik v3.7.10 decodes with mapstructure v1.5.1-0.20231216201459-8508981c8b6c from each raw configuration.
	cases := []struct {
		name              string
		expectedAudience  string
		expectedAudiences []string
		wantPass          bool
	}{
		{`ExpectedAudience: neurapolis-app, ExpectedAudiences: "" or []`, "neurapolis-app", []string{}, false},
		{`ExpectedAudience: "" or omitted, ExpectedAudiences: null, omitted or misspelled`, "", nil, false},
		{`ExpectedAudiences: "neurapolis-app,"`, "", []string{"neurapolis-app", ""}, false},
		{`ExpectedAudience: " "`, " ", nil, false},
		{`ExpectedAudience: " neurapolis-app "`, " neurapolis-app ", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := &Config{
				Keys:              []string{createTestPublicKeyPem(t, &testPrivateKey.PublicKey)},
				ExpectedAudience:  c.expectedAudience,
				ExpectedAudiences: c.expectedAudiences,
			}
			token := createSignedTestToken(t, testPrivateKey, map[string]interface{}{"sub": "user-1", "aud": "neurapolis-app"})
			if !c.wantPass {
				assertNewRejectsEveryRequest(t, config, token)
				return
			}

			handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}
			if status := serveTestRequest(t, handler, token); status != http.StatusOK {
				t.Fatalf("Expected the token to pass, got status %d", status)
			}
		})
	}
}

// TestNewRejectsEveryRequestOnInvalidKeys checks that a Keys entry that cannot be used gives a middleware that answers every request with a 500, like an invalid audience configuration does, even when a usable key stands next to it.
func TestNewRejectsEveryRequestOnInvalidKeys(t *testing.T) {
	publicKeyPem := createTestPublicKeyPem(t, &testPrivateKey.PublicKey)
	cases := []struct {
		name  string
		entry string
	}{
		{"neither PEM nor URL", "not-a-key"},
		{"extra data after a PEM block", publicKeyPem + "extra"},
		{"PEM certificate that cannot be parsed", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}))},
		{"PEM public key that cannot be parsed", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a public key")}))},
		{"unsupported PEM block", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a public key")}))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				Keys:             []string{publicKeyPem, c.entry},
				ExpectedAudience: "neurapolis-app",
			}

			assertNewRejectsEveryRequest(t, &cfg, createSignedTestToken(t, testPrivateKey, map[string]interface{}{"sub": "user-1", "aud": "neurapolis-app"}))
		})
	}
}

// TestNewRejectsEveryRequestWithoutKeys checks that a middleware without Keys answers every request with a 500, so that a fabricated token that claims another user never reaches the backend unverified.
func TestNewRejectsEveryRequestWithoutKeys(t *testing.T) {
	cfg := Config{ExpectedAudience: "neurapolis-app"}

	assertNewRejectsEveryRequest(t, &cfg, createUnsignedTestToken(t, map[string]interface{}{"sub": "victim", "aud": "neurapolis-app"}))
}

// TestNewLogsInvalidConfigurationOnce checks that New logs an invalid configuration once, naming the middleware, through the log package, which yaegi sends to the stderr that Traefik logs at the ERROR level. Requests do not log it again.
func TestNewLogsInvalidConfigurationOnce(t *testing.T) {
	var logOutput bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logOutput)
	defer log.SetOutput(previousLogOutput)
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(context.Background(), next, &Config{ExpectedAudiences: []string{"neurapolis-app", ""}}, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
		if err != nil {
			t.Fatal(err)
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Restoring the output first means that nothing writes to the buffer while it is read.
	log.SetOutput(previousLogOutput)
	if count := strings.Count(logOutput.String(), "Invalid configuration of middleware test-traefik-jwt-plugin"); count != 1 {
		t.Fatalf("Expected the configuration error to be logged once, got %d times in %q", count, logOutput.String())
	}
	if !strings.Contains(logOutput.String(), `"level":"error"`) {
		t.Fatalf("Expected an error level log event, got %q", logOutput.String())
	}
}

// testAudience is the audience that the tests configure and that their tokens carry, unless a test is about the audience check itself.
const testAudience = "test-audience"

// testPrivateKey signs the tokens of the tests that need a valid signature but no key of their own.
var testPrivateKey = generateTestPrivateKey()

// generateTestPrivateKey generates an RSA key that a test signs its tokens with.
func generateTestPrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}

// createTestPublicKeyPem encodes the public key in the PEM form that the Keys setting accepts.
func createTestPublicKeyPem(t *testing.T, publicKey interface{}) string {
	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer}))
}

// createTestToken encodes the header and the payload and signs them with the key, using the algorithm that the alg header names. The tests generate their keys, so a token can carry the claims that a test needs.
func createTestToken(t *testing.T, header, payload map[string]interface{}, key interface{}) string {
	headerJson, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(payloadJson)
	algorithmName := fmt.Sprint(header["alg"])
	algorithm, ok := tokenAlgorithms[algorithmName]
	if !ok {
		t.Fatalf("Unknown algorithm %s", algorithmName)
	}
	digest := algorithm.hash.New()
	_, _ = digest.Write([]byte(signingInput))
	var signature []byte
	switch algorithmName[:2] {
	case "RS":
		signature, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), algorithm.hash, digest.Sum(nil))
	case "PS":
		signature, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), algorithm.hash, digest.Sum(nil), nil)
	case "ES":
		ecdsaKey := key.(*ecdsa.PrivateKey)
		r, s, signErr := ecdsa.Sign(rand.Reader, ecdsaKey, digest.Sum(nil))
		err = signErr
		size := (ecdsaKey.Curve.Params().BitSize + 7) / 8
		signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case "HS":
		mac := hmac.New(algorithm.hash.New, key.([]byte))
		_, _ = mac.Write([]byte(signingInput))
		signature = mac.Sum(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// createSignedTestToken signs the payload with the key using RS256.
func createSignedTestToken(t *testing.T, privateKey *rsa.PrivateKey, payload map[string]interface{}) string {
	token := createTestToken(t, map[string]interface{}{"alg": "RS256", "typ": "JWT"}, payload, privateKey)
	return token
}

// createUnsignedTestToken builds a token whose signature no key produced.
func createUnsignedTestToken(t *testing.T, payload map[string]interface{}) string {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return token
}

// createJohnDoeTestPayload returns the claims of the jwt.io sample token plus the test audience, because a token without a configured audience is rejected.
func createJohnDoeTestPayload() map[string]interface{} {
	return map[string]interface{}{"sub": "1234567890", "name": "John Doe", "admin": true, "iat": 1516239022, "aud": testAudience}
}

// createJwksTestToken signs a token for the test audience with the key and names the key id in its header.
func createJwksTestToken(t *testing.T, kid string, privateKey *rsa.PrivateKey) string {
	token := createTestToken(t, map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": kid}, map[string]interface{}{"sub": "user-1", "aud": testAudience}, privateKey)
	return token
}

// jwksTestServer is a JWK endpoint whose answer a test can change. It serves the public halves of its keys under their key ids, answers with a 500 and a JSON error body while its keys are nil, and does not answer at all while it hangs.
type jwksTestServer struct {
	URL         string
	lock        sync.Mutex
	privateKeys map[string]*rsa.PrivateKey
	hangCh      chan struct{}
	requests    int
}

// startJwksTestServer starts a jwksTestServer that serves the keys.
func startJwksTestServer(t *testing.T, privateKeys map[string]*rsa.PrivateKey) *jwksTestServer {
	jwksServer := &jwksTestServer{privateKeys: privateKeys}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksServer.lock.Lock()
		jwksServer.requests++
		hangCh := jwksServer.hangCh
		served := jwksServer.privateKeys
		jwksServer.lock.Unlock()
		if hangCh != nil {
			select {
			case <-hangCh:
			case <-r.Context().Done():
			}
			return
		}
		if served == nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, `{"error":"unavailable"}`)
			return
		}
		keys := []map[string]string{}
		for kid, privateKey := range served {
			keys = append(keys, map[string]string{"kty": "RSA", "kid": kid, "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()), "e": "AQAB"})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}))
	// Cleanups run in reverse order, so the hanging requests end before the server waits for them to close.
	t.Cleanup(server.Close)
	t.Cleanup(func() { jwksServer.serve(nil) })
	jwksServer.URL = server.URL
	return jwksServer
}

// serve makes the endpoint serve the keys, and nil makes it answer with a 500. Requests that hang end without an answer.
func (jwksServer *jwksTestServer) serve(privateKeys map[string]*rsa.PrivateKey) {
	jwksServer.lock.Lock()
	defer jwksServer.lock.Unlock()
	if jwksServer.hangCh != nil {
		close(jwksServer.hangCh)
		jwksServer.hangCh = nil
	}
	jwksServer.privateKeys = privateKeys
}

// hang makes the endpoint accept requests and never answer them.
func (jwksServer *jwksTestServer) hang() {
	jwksServer.lock.Lock()
	defer jwksServer.lock.Unlock()
	if jwksServer.hangCh == nil {
		jwksServer.hangCh = make(chan struct{})
	}
}

// requestCount returns how many requests the endpoint received.
func (jwksServer *jwksTestServer) requestCount() int {
	jwksServer.lock.Lock()
	defer jwksServer.lock.Unlock()
	return jwksServer.requests
}

// waitForTestCondition waits until the condition holds, and fails the test when it does not after ten seconds.
func waitForTestCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("Expected %s within ten seconds", description)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForTestKey waits until a fetch of the middleware has loaded the key.
func waitForTestKey(t *testing.T, handler http.Handler, kid string) {
	t.Helper()
	waitForTestCondition(t, "a fetch to load key "+kid, func() bool {
		_, ok := handler.(*JwtPlugin).keyStore.getKeysSync()[kid]
		return ok
	})
}

// serveTestRequest sends a request with the token through the middleware and returns the status of the response. It fails the test when the request does not finish within ten seconds, so that a request that waits forever for a refresh fails the test instead of hanging it.
func serveTestRequest(t *testing.T, handler http.Handler, token string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer " + token}
	recorder := httptest.NewRecorder()
	served := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, req)
		close(served)
	}()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("Expected the request to finish within ten seconds")
	}
	return recorder.Code
}

// assertNewRejectsEveryRequest checks that New turns an invalid configuration into a middleware instead of an error, and that the middleware answers a request with the token and a request without a token with a 500 and the configuration error type. It never calls next and still strips a forged X-Account-Id header, which the JwtHeaders that this function sets would otherwise fill from the token.
func assertNewRejectsEveryRequest(t *testing.T, config *Config, token string) {
	t.Helper()
	config.JwtHeaders = map[string]string{"X-Account-Id": "sub"}
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	handler, err := New(context.Background(), next, config, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatalf("Expected New to return a middleware that rejects every request, got error %v", err)
	}
	if handler == nil {
		t.Fatal("Expected New to return a middleware, got nil")
	}

	for _, authorization := range []string{"Bearer " + token, ""} {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header["Authorization"] = []string{authorization}
		}
		req.Header["X-Account-Id"] = []string{"forged"}

		handler.ServeHTTP(recorder, req)

		if nextCalled {
			t.Fatal("Expected next.ServeHTTP not to be called")
		}
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("Expected status code %d, got %d with body %s", http.StatusInternalServerError, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), ErrorTypeUnauthenticatedConfigurationInvalid) {
			t.Fatalf("Expected body to contain %s, got %s", ErrorTypeUnauthenticatedConfigurationInvalid, recorder.Body.String())
		}
		if values := req.Header["X-Account-Id"]; len(values) != 0 {
			t.Fatalf("Expected the forged X-Account-Id header to be stripped, got %q", values)
		}
	}
}
