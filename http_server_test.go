package main

import (
	"bytes"
	"encoding/json"
	"github.com/bitly/go-simplejson"
	"github.com/gin-gonic/gin"
	gopwned "github.com/mavjs/goPwned"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthRoute(t *testing.T) {
	router := createTestServer()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestGoodPlaintextPassword(t *testing.T) {
	router := createTestServer()

	w := httptest.NewRecorder()
	req := buildPasswordRequest("The Chargers Win The Superbowl!")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"acceptable\":true}", w.Body.String())
}

func TestBadPlaintextPassword(t *testing.T) {
	router := createTestServer()

	w := httptest.NewRecorder()
	req := buildPasswordRequest("Test123")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"acceptable\":false,\"reason\":\"password too short\"}", w.Body.String())
}

func TestCompromisedPlaintextPassword(t *testing.T) {
	router := createTestServer()

	w := httptest.NewRecorder()
	req := buildPasswordRequest("Test987654321")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "{\"acceptable\":false,")
}

func TestBannedPasswordsList(t *testing.T) {
	router := createTestServer()

	w := httptest.NewRecorder()
	req := buildPasswordRequest("myCompany")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	resp, _ := simplejson.NewFromReader(w.Body)
	accept, _ := resp.Get("acceptable").Bool()
	reason, _ := resp.Get("reason").String()
	assert.Equal(t, false, accept)
	assert.Equal(t, "Password disallowed", reason)
}

func createTestServer() *gin.Engine {
	bannedPasswords := NewBannedPasswordsList("./data/disallow.txt")
	gopwned := gopwned.NewClient(nil, "")

	router := setupRouter(gopwned, bannedPasswords)
	return router
}

func buildPasswordRequest(password string) *http.Request {
	p := Password{Password: password}
	body, _ := json.Marshal(p)
	req, _ := http.NewRequest("POST", "/password/plaintext", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}
