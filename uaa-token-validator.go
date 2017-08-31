package cffly

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTValidator must be able to validate an access token, veirfy it matches a client ID, and return a map of claims
type JWTValidator interface {
	ValidateAccessToken(at, expectedClientID string) (jwt.MapClaims, error)
}

// UAAJWTValidator will validate access tokens against a UAA instance, caching keys as required
type UAAJWTValidator struct {
	// UAAURL is the URL to UAA, e.g. https://uaa.system.example.com
	UAAURL string

	// Internal, lock for cached public keys
	cachedKeysLock sync.RWMutex

	// Public key map
	cachedKeys map[string]*rsa.PublicKey
}

// Return public key for a given key ID, if we have it, else nil is returned
func (lh *UAAJWTValidator) pubKeyForID(kid string) *rsa.PublicKey {
	lh.cachedKeysLock.RLock()
	defer lh.cachedKeysLock.RUnlock()

	if lh.cachedKeys == nil {
		return nil
	}

	rv, ok := lh.cachedKeys[kid]
	if !ok {
		return nil
	}

	return rv
}

// Contact UAA to fetch latest public key, and if it matches the key ID requested,
// then return it, else an error will be returned.
func (lh *UAAJWTValidator) fetchAndSaveLatestKey(idWanted string) (*rsa.PublicKey, error) {
	resp, err := http.Get(lh.UAAURL + "/token_key")
	if err != nil {
		return nil, err
	}

	var dd struct {
		ID  string `json:"kid"`
		PEM string `json:"value"`
	}
	err = json.NewDecoder(resp.Body).Decode(&dd)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}

	pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(dd.PEM))
	if err != nil {
		return nil, err
	}

	lh.cachedKeysLock.Lock()
	defer lh.cachedKeysLock.Unlock()

	if lh.cachedKeys == nil {
		lh.cachedKeys = make(map[string]*rsa.PublicKey)
	}

	// With old verions of CF, the KID will be empty. That seems OK as it'll now be empty here too.
	lh.cachedKeys[dd.ID] = pk

	if dd.ID != idWanted {
		return nil, errors.New("still can't find it")
	}

	return pk, nil
}

// Find the public key to verify the JWT, and check the algorithm.
func (lh *UAAJWTValidator) cfKeyFunc(t *jwt.Token) (interface{}, error) {
	// Ensure that RS256 is used. This might seem overkill to care,
	// but since the JWT spec actually allows a None algorithm which
	// we definitely don't want, so instead we whitelist what we will allow.
	if t.Method.Alg() != "RS256" {
		return nil, errors.New("bad token9")
	}

	// Get Key ID
	kid, ok := t.Header["kid"]
	if !ok {
		kid = "" // some versions of CloudFoundry don't return a key ID - if so, let's just hope for the best
	}

	kidS, ok := kid.(string)
	if !ok {
		return nil, errors.New("bad token 11")
	}

	rv := lh.pubKeyForID(kidS)
	if rv != nil {
		return rv, nil
	}

	rv, err := lh.fetchAndSaveLatestKey(kidS)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

// ValidateAccessToken will validate the given access token, ensure it matches the client ID, and return the claims reported within.
func (lh *UAAJWTValidator) ValidateAccessToken(at, expectedClientID string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(at, lh.cfKeyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("bad token 1")
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("bad token 2")
	}

	if !mapClaims.VerifyIssuer(lh.UAAURL+"/oauth/token", true) {
		return nil, errors.New("bad token 3")
	}

	// Never, ever, ever, skip a client ID check (common error)
	cid, _ := mapClaims["client_id"].(string)
	if cid != expectedClientID {
		return nil, errors.New("very bad token 4")
	}

	return mapClaims, nil
}
