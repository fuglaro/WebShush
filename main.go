package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
)

//go:embed resources
//go:embed favicon.ico
var res embed.FS

var version string

var defaultHostname = "localhost"
var upgrader = websocket.Upgrader{}
var privateKey = make([]byte, 512/8)
var connectionID atomic.Uint64 // sequential ID generator making keys for connections.
var connections = map[uint64]*ssh.Client{}
var connectionsSFTP = map[uint64]*sftp.Client{}

// Attempt to find the Client IP (without the port) for an incomming request.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	for _, header := range []string{"X-Client-IP", "X-Forwarded-For", "X-Real-IP"} {
		v := r.Header.Get(header)
		if v != "" {
			ip = v
			break
		}
	}
	return strings.SplitN(strings.SplitN(ip, ",", 2)[0], ":", 2)[0]
}

/**
 * Checks if the passed in error has a value and, if it does,
 * a StatusForbidden error is provided to the response.
 * For the purposes of this webserver, where we are exposing
 * files via SFTP, assuming any error relates to a permission
 * issue, is sufficient. It breaks some HTTP conventions but
 * its nice and simple.
 * Returns whether the error had a value.
 */
func check(w http.ResponseWriter, e error) bool {
	if e != nil {
		http.Error(w, e.Error(), http.StatusForbidden)
	}
	return e != nil
}

/**
 * Similar to the check function, this checks and on encountering
 * an error, will send a websocket message indicating the error,
 * then will return false so the websocket can be dropped.
 */
func checkInWS(c *websocket.Conn, mutex *sync.Mutex, id int, e error) bool {
	if e != nil {
		mutex.Lock()
		_ = c.WriteJSON(map[string]interface{}{"id": id, "err": e.Error()})
		mutex.Unlock()
	}
	return e != nil
}

/**
 * Establish a websocket connection,
 * authenticate against making a new ssh connection,
 * then start responding to storage, terminal, and action plugin requests.
 */
func connect(w http.ResponseWriter, r *http.Request) {
	// Ensure the __Host-SecSiteSameOrigin cookie previously fetched from /preconnect
	// validly indicates that the request is coming from the same origin, in case
	// some browsers don't send Secure Fetch Metadata headers with websocket connections.
	ts, err := r.Cookie("__Host-SecSiteSameOrigin")
	if check(w, err) {
		return
	}
	_, err = jwt.Parse(ts.Value,
		func(token *jwt.Token) (interface{}, error) {
			return privateKey, nil
		},
		jwt.WithValidMethods([]string{"HS512"}),
		jwt.WithAudience(clientIP(r)),
		jwt.WithExpirationRequired())
	if check(w, err) {
		return
	}
	// Ensure Secure Fetch Metadata validity.
	if (r.Header.Get("Sec-Fetch-Site") != "same-origin" ||
		r.Header.Get("Sec-Fetch-Mode") != "websocket" ||
		(r.Header.Get("Sec-Fetch-Dest") != "empty" && r.Header.Get("Sec-Fetch-Dest") != "websocket")) &&
		// Ignore these if they are missing, which is safe only because we have checked
		// the validity of the __Host-SecSiteSameOrigin cookie proving the request is same origin.
		(0 != len(r.Header.Values("Sec-Fetch-Site"))+
			len(r.Header.Values("Sec-Fetch-Mode"))+
			len(r.Header.Values("Sec-Fetch-Dest"))) {
		http.Error(w, "Invalid Secure Fetch Metadata", http.StatusForbidden)
		return
	}
	csrfcookie, err := r.Cookie("__Host-CSRFToken")
	if check(w, err) {
		return
	}
	// Establish Websocket connection.
	c, err := upgrader.Upgrade(w, r, nil)
	if check(w, err) {
		return
	}
	var mutex sync.Mutex // Websocket writer mutex.
	defer c.Close()
	_, csrf64, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	// Validate the CSRF Token
	csrf, err := base64.URLEncoding.DecodeString(string(csrf64))
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	csrfhash, err := base64.URLEncoding.DecodeString(string(csrfcookie.Value))
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	hash := hmac.New(sha256.New, privateKey)
	hash.Write(csrf)
	if !hmac.Equal([]byte(csrfhash), hash.Sum(nil)) {
		checkInWS(c, &mutex, -99, errors.New("Invalid CSRFToken"))
		return
	}
	// Authenticate and establish SSH connection.
	_, user, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	// Parse the user into username, host, and port, with defaults.
	hostname := defaultHostname
	userhost := strings.SplitN(string(user), "@", 2)
	username := userhost[0]
	if len(userhost) > 1 {
		hostname = userhost[1]
	}
	if !strings.Contains(hostname, ":") {
		hostname += ":22"
	}
	_, pass, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	_, code, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	_, hostkey, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	_, shell, err := c.ReadMessage()
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	var codeUsed = false
	hostKeyManager := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		realkey := base64.StdEncoding.EncodeToString(key.Marshal())
		if string(hostkey) != "" && string(hostkey) != realkey {
			if c.WriteJSON("") != nil {
				return fmt.Errorf("Bad Host Key Error Send Failure")
			}
			return fmt.Errorf("Bad Host Key")
		}
		// Send the realkey to the client for reference.
		if c.WriteJSON(map[string]interface{}{"hostname": hostname, "hostkey": realkey}) != nil {
			return fmt.Errorf("Host Key Send Failure")
		}

		return nil
	}
	sshConn, err := ssh.Dial("tcp", hostname, &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
					answ := make([]string, len(questions))
					for i, q := range questions {
						answ[i] = string(pass)
						if strings.Contains(strings.ToLower(q), "code") {
							answ[i] = string(code)
							codeUsed = true
						}
					}
					return answ, nil
				}),
			ssh.Password(string(pass))},
		HostKeyCallback: hostKeyManager,
	})
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	defer sshConn.Close()
	if len(code) != 0 && !codeUsed {
		// If code was given, but code was not used in authentication, assume malice and abort.
		time.Sleep(3 * time.Second) // Frustrate urge to reattempt.
		return
	}

	// Setup for management of the terminal shell sessions.
	var sessRunning = false
	var sess *ssh.Session
	var sessIn io.WriteCloser
	runSession := func() {
		if sessRunning { // Reuse existing sessions if available.
			return
		}
		sess, err = sshConn.NewSession()
		if checkInWS(c, &mutex, -99, err) {
			c.Close()
			return
		}
		sessIn, err = sess.StdinPipe()
		if checkInWS(c, &mutex, -99, err) {
			sess.Close()
			c.Close()
			return
		}
		sessOut, err := sess.StdoutPipe()
		if checkInWS(c, &mutex, -99, err) {
			sess.Close()
			c.Close()
			return
		}
		sess.Stderr = os.Stderr
		_ = sess.Setenv("LANG", "C.UTF-8")
		_ = sess.Setenv("COLORTERM", "truecolor")
		if err = sess.RequestPty("xterm-256color", 80, 40, nil); err != nil {
			_ = checkInWS(c, &mutex, -99, err)
			sess.Close()
			c.Close()
			return
		}
		if string(shell) == "" {
			err = sess.Shell()
		} else {
			err = sess.Start(string(shell))
		}
		if err != nil {
			_ = checkInWS(c, &mutex, -99, err)
			sess.Close()
			c.Close()
			return
		}
		sessRunning = true
		// Proxy data between the websocket and the ssh session, in the background.
		go func() {
			buf := make([]byte, 20000)
			for {
				// Ferry data coming out of the ssh shell into the websocket.
				n, rerr := sessOut.Read(buf)
				mutex.Lock()
				mw, err := c.NextWriter(websocket.BinaryMessage)
				if err != nil {
					sess.Close()
					mutex.Unlock()
					c.Close()
					return
				}
				mw.Write([]byte("1")) // term header
				mw.Write(buf[:n])
				if mw.Close() != nil {
					sess.Close()
					mutex.Unlock()
					c.Close()
					return
				}
				if rerr != nil {
					sessRunning = false
					sess.Close()
					mutex.Unlock()
					if rerr != io.EOF {
						_ = checkInWS(c, &mutex, -99, err)
						c.Close()
					} else if c.WriteMessage( /* Send a term closed message */
						websocket.BinaryMessage, []byte("0")) != nil {
						c.Close()
					}
					return
				}
				mutex.Unlock()
			}
		}()
	}

	// Wrap SSH connection with SFTP interface.
	sftpc, err := sftp.NewClient(sshConn)
	if checkInWS(c, &mutex, -99, err) {
		return
	}
	// Associate the connection with a unique ID for subsequent authenticated access.
	connID := connectionID.Add(1)
	connections[connID] = sshConn
	connectionsSFTP[connID] = sftpc
	// Ensure the connection is cleared when the WebSocket connection closes.
	defer delete(connections, connID)
	defer delete(connectionsSFTP, connID)
	// Handle messages on the established authenticated connection.
	type Msg struct {
		Rows int
		Cols int
	}
	for {
		// Wait for the next message.
		mtype, re, err := c.NextReader()
		if checkInWS(c, &mutex, -99, err) {
			return
		}

		/* Process the message and respond. */

		// Ferry input to the server
		if mtype == websocket.BinaryMessage {
			if _, err = io.Copy(sessIn, re); checkInWS(c, &mutex, -99, err) {
				return
			}
			continue
		}

		// Handle control messages
		m := Msg{}
		mstr, err := io.ReadAll(re)
		err = json.Unmarshal(mstr, &m)
		if checkInWS(c, &mutex, -99, err) {
			return
		}
		if m.Rows == -1 {
			runSession()
			continue
		}
		if !sessRunning {
			continue // Probaly just ignorable leftover messages in transit after an ended session.
		}
		if m.Rows != 0 {
			sess.WindowChange(m.Rows, m.Cols)
			continue
		}
	}
}

func main() {
	// Handle options.
	if h := os.Getenv("WEBSHUSH_DEFAULT_HOST"); h != "" {
		fmt.Fprintf(os.Stderr, "WEBSHUSH_DEFAULT_HOST=%v\n", h)
		defaultHostname = h
	}
	addr := os.Getenv("WEBSHUSH_LISTEN")
	if addr == "" {
		addr = ":443"
	}
	cert := os.Getenv("WEBSHUSH_CERT_FILE")
	key := os.Getenv("WEBSHUSH_KEY_FILE")
	domain := os.Getenv("WEBSHUSH_DOMAIN")
	if domain == "" && (cert == "" || key == "") {
		fmt.Print(`
webshush: The lean and powerful 💪 personal cloud ⛅.

Usage:
  WEBSHUSH_CERT_FILE=my.crt WEBSHUSH_KEY_FILE=my.key webshush

Environment Variables:
  WEBSHUSH_CERT_FILE:
  WEBSHUSH_KEY_FILE:
    The credentials to use for TLS connections.
  WEBSHUSH_DOMAIN:
    The domain to use with the included Let's Encrypt integration.
    Use of this implies acceptance of the LetsEncrypt Terms of Service.
  WEBSHUSH_LISTEN:
    The address to listen on. Defaults to :443.

This service can only be served over HTTPS connections, requiring
either WENSHUSH_CERT_FILE and WEBSHUSH_KEY_FILE to be specified, or,
if you accept the LetsEncrypt Terms of Service, you can use the
automatic LetsEncrypt configuration by specifying WEBSHUSH_DOMAIN.

VERSION: ` + version + "\n")
		return
	}

	// Set up the standard security middleware.
	SMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Vary", "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site")
			w.Header().Set("Cache-Control", "max-age=36000")
			next.ServeHTTP(w, r)
		})
	}

	// Redirect HTTP to HTTPS.
	go func() {
		log.Println(http.ListenAndServe(":8080",
			SMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirect := "https://" + strings.Split(r.Host, ":")[0]
				if strings.Contains(addr, ":") {
					redirect += ":" + strings.Split(addr, ":")[1]
				}
				http.Redirect(w, r, redirect+r.URL.Path, http.StatusTemporaryRedirect)
			}))))
	}()

	// Generate private key for JWT signing.
	_, err := rand.Read(privateKey)
	if err != nil {
		log.Fatal("Failed to generate cryptographically secure pseudorandom private JWT signing key.")
		return
	}

	// Serve connection endpoints.
	http.Handle("/connect", SMW(http.HandlerFunc(connect)))
	http.Handle("/preconnect", SMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure Secure Fetch Metadata validity.
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" ||
			r.Header.Get("Sec-Fetch-Dest") != "empty" {
			http.Error(w, "Invalid Secure Fetch Metadata", http.StatusForbidden)
			return
		}
		// Prepare the JWT for the brief __Host-SecSiteSameOrigin cookie so,
		// the /connect endpoint can validate the request is same-origin,
		// even when the browser doesn't bother to send Secure Fetch Metadata
		// with websocket requests. (I'm looking at you Chrome as of Version 123.0.6312.124)
		t := jwt.NewWithClaims(jwt.SigningMethodHS512, &jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{clientIP(r)},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 3))})
		s, err := t.SignedString(privateKey)
		if check(w, err) {
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-SecSiteSameOrigin",
			Value:    s,
			MaxAge:   3,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	})))

	// The main page.
	http.Handle("/", SMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure Secure Fetch Metadata validity.
		if r.Header.Get("Sec-Fetch-Dest") != "document" {
			http.Error(w, "Invalid Secure Fetch Metadata", http.StatusForbidden)
			return
		}
		// Set up security cookies.
		nonceb := make([]byte, 128/8)
		_, err = rand.Read(nonceb)
		if check(w, err) {
			return
		}
		nonce := base64.URLEncoding.EncodeToString(nonceb)
		w.Header().Set("Content-Security-Policy", "sandbox allow-downloads allow-forms "+
			"allow-same-origin allow-scripts allow-modals; "+
			"default-src 'none'; frame-ancestors 'none'; "+
			"form-action 'none'; img-src 'self'; media-src 'self'; font-src 'self'; "+
			"connect-src 'self'; style-src-elem 'self' 'unsafe-inline'; "+
			"style-src-attr 'unsafe-inline'; style-src 'self'; "+
			"script-src-elem 'self' 'nonce-"+nonce+"';")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Referrer-Policy", "same-origin")
		t, err := template.ParseFS(res, "resources/main.html")
		if check(w, err) {
			return
		}
		// Prepare a Singed Double Submit Cookie CSRF Token.
		var hashData = make([]byte, 512/8)
		_, err = rand.Read(hashData)
		if err != nil {
			log.Fatal("Failed to generate cryptographically secure CSRF random identifier.")
			return
		}
		hash := hmac.New(sha256.New, privateKey)
		hash.Write(hashData)
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-CSRFToken",
			Value:    base64.URLEncoding.EncodeToString(hash.Sum(nil)),
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Cache-Control", "no-cache")
		// Resolve template and send.
		t.Execute(w, struct {
			Nonce string
			CSRF  string
		}{Nonce: nonce, CSRF: base64.URLEncoding.EncodeToString(hashData)})
	})))
	http.Handle("/resources/", SMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure Secure Fetch Metadata validity.
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" ||
			(r.Header.Get("Sec-Fetch-Dest") != "script" &&
				r.Header.Get("Sec-Fetch-Dest") != "style" &&
				r.Header.Get("Sec-Fetch-Dest") != "font") {
			http.Error(w, "Invalid Secure Fetch Metadata", http.StatusForbidden)
			return
		}
		http.FileServerFS(res).ServeHTTP(w, r)
	})))
	http.Handle("/favicon.ico", SMW(http.FileServerFS(res)))

	// Display final configuration information and then launch service.
	fmt.Fprintf(os.Stderr, "WEBSHUSH_CERT_FILE=%v\n", cert)
	fmt.Fprintf(os.Stderr, "WEBSHUSH_KEY_FILE=%v\n", key)
	fmt.Fprintf(os.Stderr, "WEBSHUSH_DOMAIN=%v\n", domain)
	fmt.Fprintf(os.Stderr, "WEBSHUSH_LISTEN=%v\n", addr)
	fmt.Fprintf(os.Stderr, "\nListening...\n")
	if os.Getenv("WEBSHUSH_DOMAIN") != "" {
		log.Fatal(http.Serve(autocert.NewListener(domain), nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(addr, cert, key, nil))
	}
}
