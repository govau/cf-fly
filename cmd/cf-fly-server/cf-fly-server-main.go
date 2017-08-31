package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	"github.com/gorilla/mux"
	cffly "github.com/govau/cf-fly"
)

type ttlBytes struct {
	Bytes []byte
	KeyID string
	TTL   time.Time
}

type cfFlyServer struct {
	CFAPIURL       string // e.g. https://api.system.example.com
	UAAAPIClientID string // as configured in UAA
	JWTValidator   cffly.JWTValidator

	// Internal
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
	return s.rotateSigningKey()
}

// generate a new key for signing, discard old ones
func (s *cfFlyServer) rotateSigningKey() error {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	n := time.Now()

	nvb := n.Add(-5 * time.Minute) // give a bit of slop
	nva := nvb.Add(24 * time.Hour)

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
		if thing.TTL.After(n) {
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

	// First make sure it was intended for us
	_, err := s.JWTValidator.ValidateAccessToken(t, s.UAAAPIClientID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Next extract the user_id from /userinfo -> {
	//"user_id" : "xxxx",

	// Then see if we are a SpaceDeveloper
	// cli.ListUserSpaces(uuid)

	//spaceUUID := r.FormValue("space")

	cli := &cfclient.Config{
		ApiAddress: s.CFAPIURL,
	}

	w.Header().Set("Content-Type", "application/json")
	//w.Write(v)
}

func (s *cfFlyServer) CreateHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/keys", s.keyHandler)
	r.HandleFunc("/v1/sign", s.signHandler)
	return r
}

func main() {
	server := &cfFlyServer{}
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}
	http.ListenAndServe(":8090", server.CreateHandler())
}
