package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	//"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"
	flag "github.com/spf13/pflag"
)

// Claims stores the values we want to extract from the JWT as JSON
type Claims struct {
	Email string `json:"email"`
}

type LocalIpv4 struct {
	ip   uint32
	mask uint32
}

var (
	// default flag values
	authDomain = ""
	allowLocal = false
	address    = ""
	port       = 80
	localIpv4  = []LocalIpv4{
		{0xa000000, 0xff000000},
		{0xac100000, 0xfff00000},
		{0xc0a80000, 0xffff0000},
	}

	// jwt signing keys
	keySet oidc.KeySet
)

func init() {

	// parse flags
	flag.StringVar(&authDomain, "auth-domain", authDomain, "authentication domain (https://foo.cloudflareaccess.com)")
	flag.BoolVar(&allowLocal, "allow-local", allowLocal, "allow local IPv4 addresses")
	flag.IntVar(&port, "port", port, "http port to listen on")
	flag.StringVar(&address, "address", address, "http address to listen on (leave empty to listen on all interfaces)")
	flag.Parse()

	// --auth-domain is required
	if authDomain == "" {
		fmt.Println("ERROR: Please set --auth-domain to the authorization domain you configured on cloudflare. Should be like `https://foo.cloudflareaccess.com`")
		flag.Usage()
		os.Exit(1)
	}

	// configure keyset
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", authDomain)
	keySet = oidc.NewRemoteKeySet(context.TODO(), certsURL)

}

func main() {

	// set up routes
	router := httprouter.New()
	router.GET("/auth/:audience", authHandler)

	// listen
	addr := fmt.Sprintf("%s:%d", address, port)
	log.Printf("Listening on %s", addr)
	log.Fatalln(http.ListenAndServe(addr, router)) // handlers.LoggingHandler(os.Stdout, router)))

}

func isLocalIpv4(ipv4 string) bool {
	ipObj := net.ParseIP(ipv4)
	if ipObj == nil {
		return false
	}

	ipObj = ipObj.To4()
	if ipObj == nil {
		return false
	}

	ip := binary.BigEndian.Uint32(ipObj)
	for _, localIp := range localIpv4 {
		if (ip & localIp.mask) == localIp.ip {
			return true
		}
	}

	return false
}

func authHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	// Get audience from request params
	audience := ps.ByName("audience")

	// Configure verifier
	config := &oidc.Config{
		ClientID: audience,
	}
	verifier := oidc.NewVerifier(authDomain, keySet, config)

	// Make sure that the incoming request has our token header
	//  Could also look in the cookies for CF_AUTHORIZATION
	accessJWT := r.Header.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		var client_ip = r.Header.Get("X-Real-IP")
		if client_ip != "" && allowLocal && isLocalIpv4(client_ip) {
			write(w, http.StatusOK, "")
			return
		}
		write(w, http.StatusUnauthorized, "No token on the request")
		return
	}

	// Verify the access token
	ctx := r.Context()
	idToken, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		write(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %s", err.Error()))
		return
	}

	// parse the claims
	claims := Claims{}
	err = idToken.Claims(&claims)
	if err != nil {
		write(w, http.StatusUnauthorized, fmt.Sprintf("Invalid claims: %s", err.Error()))
		return
	}

	// Request is good to go
	w.Header().Set("X-Auth-User", claims.Email)
	write(w, http.StatusOK, "")

}

func write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	if body != "" {
		_, err := w.Write([]byte(body))
		if err != nil {
			log.Printf("Error writing body: %s\n", err)
		}
	}
}
