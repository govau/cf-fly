package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	cfcommon "github.com/govau/cf-common"
	cffly "github.com/govau/cf-fly"
)

type ttlBytes struct {
	Bytes []byte
	KeyID string
	TTL   time.Time
}

type cfFlyServer struct {
	CFAPIURL        string // e.g. https://api.system.example.com
	UAAAPIClientID  string // as configured in UAA
	AudienceToStamp string // put into tokens

	// Internal
	uaaClient *cfcommon.UAAClient

	keyLock sync.RWMutex

	// current key
	curPrivateKey *rsa.PrivateKey
	currentKeyID  string
	currentTTL    time.Time

	// source material
	allKeys []*ttlBytes

	// to serve
	publicKeys []byte
}

// Init must be called at server start
func (s *cfFlyServer) Init() error {
	var err error
	s.uaaClient, err = cfcommon.NewUAAClientFromAPIURL(s.CFAPIURL)
	if err != nil {
		return err
	}
	err = s.rotateSigningKey(time.Now().Add(time.Hour * 24))
	if err != nil {
		return err
	}

	return nil
}

func (s *cfFlyServer) getCurrentKey(desiredTTL time.Time) (*rsa.PrivateKey, string, error) {
	for i := 0; i < 2; i++ {
		s.keyLock.RLock()
		k := s.curPrivateKey
		t := s.currentTTL
		i := s.currentKeyID
		s.keyLock.RUnlock()

		// Make sure we're good for at least an hour
		if t.After(desiredTTL) {
			return k, i, nil
		}

		err := s.rotateSigningKey(desiredTTL)
		if err != nil {
			return nil, "", err
		}
	}
	return nil, "", errors.New("took too long")
}

// generate a new key for signing, discard old ones. New one will be valid at least the length of the desired
func (s *cfFlyServer) rotateSigningKey(desiredTTL time.Time) error {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// give a bit of slop
	now := time.Now().Add(-5 * time.Minute)

	nvb := now
	nva := desiredTTL.Add(1 * time.Hour)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &newKey.PublicKey,
		NotAfter:     nva,
		NotBefore:    nvb,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &newKey.PublicKey, newKey)
	if err != nil {
		return err
	}

	// re-parse the cert so that we can get the raw fields that we want for hashing
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	newKeyID := hex.EncodeToString(spkiHash[:])

	s.keyLock.Lock()
	defer s.keyLock.Unlock()

	var newAll []*ttlBytes
	toSerial := make(cffly.CertificateMap)
	for _, thing := range append(s.allKeys, &ttlBytes{Bytes: certBytes, TTL: nva, KeyID: newKeyID}) {
		if thing.TTL.After(now) {
			newAll = append(newAll, thing)
			toSerial[thing.KeyID] = thing.Bytes
		}
	}

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(toSerial)
	if err != nil {
		return err
	}

	s.curPrivateKey = newKey
	s.currentKeyID = newKeyID
	s.currentTTL = nva
	s.allKeys = newAll
	s.publicKeys = b.Bytes()

	return nil
}

func (s *cfFlyServer) keyHandler(w http.ResponseWriter, r *http.Request) {
	s.keyLock.RLock()
	v := s.publicKeys
	s.keyLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write(v)
}

func (s *cfFlyServer) signHandler(w http.ResponseWriter, r *http.Request) {
	t := r.Header.Get("Authorization")
	parts := strings.Split(t, " ")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	at := parts[1]

	// First make sure it was intended for us
	og, err := s.uaaClient.ValidateAccessToken(at, s.UAAAPIClientID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	userID, _ := og["user_id"].(string)
	if userID == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	email, _ := og["email"].(string)
	if email == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	spaceID := r.FormValue("space")
	if spaceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cli, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress: s.CFAPIURL,
		Token:      at,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	space, err := cli.GetSpaceByGuid(spaceID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	roles, err := space.Roles()
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	allowed := false
	for _, sr := range roles {
		if sr.Guid == userID {
			for _, r := range sr.SpaceRoles {
				if r == "space_developer" {
					allowed = true
					break
				}
			}
		}
	}
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	org, err := space.Org()
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ttl := time.Now().Add(4 * time.Hour)
	pkey, keyID, err := s.getCurrentKey(ttl)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	displayName := fmt.Sprintf("Org: %s / Space: %s", org.Name, space.Name)
	storeName := fmt.Sprintf("cf:%s", space.Guid)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		// Concourse normal claims
		"exp":      ttl.Unix(),
		"teamName": storeName,
		"isAdmin":  false,
		"csrf":     "",

		// Our own
		"kid":              keyID,             // to find which key to verify against
		"aud":              s.AudienceToStamp, // in case the same server matches multiple Concourses
		"createIfNotExist": true,              // create the team if it doesn't exist
		"emailAddress":     email,             // for audit logging
		"displayTeamName":  displayName,
	})

	signed, err := jwtToken.SignedString(pkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Signed token for %s in team: %s / %s\n", email, org.Name, space.Name)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(signed))
}

func (s *cfFlyServer) CreateHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/keys", s.keyHandler)
	r.HandleFunc("/v1/sign", s.signHandler)
	return r
}

func main() {
	server := &cfFlyServer{
		CFAPIURL:        os.Getenv("CF_API"),
		UAAAPIClientID:  "cf-concourse-integration",
		AudienceToStamp: "concourse",
	}
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Serving...")
	http.ListenAndServe(":"+os.Getenv("PORT"), server.CreateHandler())
}
