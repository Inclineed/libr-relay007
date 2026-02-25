package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"context"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	relay "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

type RelayDist struct {
	relayID string
	dist    *big.Int
}

const ChatProtocol = protocol.ID("/chat/1.0.0")

//var RelayMultiAddrList = []string{"/dns4/0.tcp.in.ngrok.io/tcp/14395/p2p/12D3KooWLBVV1ty7MwJQos34jy1WqGrfkb3bMAfxUJzCgwTBQ2pn",}

// reqFormat mirrors the struct used in mod_client/peers/peer.go.
// PeerID is the libp2p peer ID string of the target peer.
type reqFormat struct {
	Type      string          `json:"type,omitempty"`
	PeerID    string          `json:"peer_id,omitempty"`
	ReqParams json.RawMessage `json:"reqparams,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
}

var (
	IDmap = make(map[string]string)
	mu    sync.RWMutex
)

var RelayHost host.Host

type respFormat struct {
	Type string `json:"type"`
	Resp []byte `json:"resp"`
}

type RelayEvents struct{}

func (re *RelayEvents) Listen(net network.Network, addr ma.Multiaddr)      {}
func (re *RelayEvents) ListenClose(net network.Network, addr ma.Multiaddr) {}
func (re *RelayEvents) Connected(net network.Network, conn network.Conn) {
	fmt.Printf("[INFO] Peer connected: %s\n", conn.RemotePeer())
}
func (re *RelayEvents) Disconnected(net network.Network, conn network.Conn) {
	fmt.Printf("[INFO] Peer disconnected: %s\n", conn.RemotePeer())
	// Remove peer from IDmap if needed
	mu.Lock()
	for pid := range IDmap {
		if pid == conn.RemotePeer().String() {
			delete(IDmap, pid)
			break
		}
	}
	mu.Unlock()
}

// serverURL is read from the SERVER_URL environment variable.
// Set it to the base URL of your deployed librserver, e.g.:
//   https://libr-relay007-1.onrender.com
var serverURL string

const relayKeyFile = "relay_priv_key.bin"

// loadOrGenerateKey loads a persisted Ed25519 private key from disk, or
// generates and saves a new one. The key is used for challenge-response
// authentication with librserver so the same publicKey survives restarts.
func loadOrGenerateKey() (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(relayKeyFile)
	if err == nil && len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generateKey: %w", err)
	}
	if err := os.WriteFile(relayKeyFile, priv, 0600); err != nil {
		log.Printf("[WARN] Could not persist relay key: %v", err)
	}
	return priv, nil
}

// loadOrGenerateLibp2pKey returns a stable libp2p identity key.
// It reads the LIBP2P_PRIV_KEY env var (base64-encoded protobuf marshalled key).
// If the env var is absent it generates a fresh key, prints its base64 value,
// and continues — set that printed value as LIBP2P_PRIV_KEY in Render's
// environment-variable dashboard so the peer ID is stable on restarts.
func loadOrGenerateLibp2pKey() (libp2pcrypto.PrivKey, error) {
	if b64 := os.Getenv("LIBP2P_PRIV_KEY"); b64 != "" {
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("loadOrGenerateLibp2pKey: base64 decode: %w", err)
		}
		key, err := libp2pcrypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("loadOrGenerateLibp2pKey: unmarshal: %w", err)
		}
		log.Println("[INFO] Loaded libp2p identity from LIBP2P_PRIV_KEY env var")
		return key, nil
	}
	// No env var — generate a fresh key for this run.
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("loadOrGenerateLibp2pKey: generate: %w", err)
	}
	marshalled, err := libp2pcrypto.MarshalPrivateKey(priv)
	if err == nil {
		log.Printf("[WARN] LIBP2P_PRIV_KEY not set. Peer ID will change on next restart.\n"+
			"      Set this env var to make it stable:\n      LIBP2P_PRIV_KEY=%s",
			base64.StdEncoding.EncodeToString(marshalled))
	}
	return priv, nil
}

// getChallenge fetches a one-time nonce from librserver.
func getChallenge(pubKeyB64 string) (string, error) {
	endpoint := fmt.Sprintf("%s/auth/challenge?publicKey=%s", serverURL, url.QueryEscape(pubKeyB64))
	resp, err := http.Get(endpoint)
	if err != nil {
		return "", fmt.Errorf("getChallenge: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getChallenge: server returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("getChallenge: decode: %w", err)
	}
	return result.Nonce, nil
}

// signedPost performs challenge → sign → POST for librserver authenticated endpoints.
func signedPost(endpoint string, pubKeyB64 string, priv ed25519.PrivateKey, extra map[string]string) error {
	nonce, err := getChallenge(pubKeyB64)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, []byte(nonce))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	body := map[string]string{
		"publicKey": pubKeyB64,
		"nonce":     nonce,
		"signature": sigB64,
	}
	for k, v := range extra {
		body[k] = v
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("signedPost: marshal: %w", err)
	}
	resp, err := http.Post(serverURL+endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("signedPost %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("signedPost %s: server returned %d: %s", endpoint, resp.StatusCode, b)
	}
	return nil
}

// registerRelayWithServer registers this relay's multiaddr with librserver.
func registerRelayWithServer(multiaddr string, pubKeyB64 string, priv ed25519.PrivateKey) error {
	if err := signedPost("/relays/register", pubKeyB64, priv, map[string]string{"address": multiaddr}); err != nil {
		log.Printf("[ERROR] Failed to register relay with server: %v", err)
		return err
	}
	log.Println("[INFO] Relay registered with librserver")
	return nil
}

// deregisterRelayFromServer removes this relay from librserver on shutdown.
func deregisterRelayFromServer(pubKeyB64 string, priv ed25519.PrivateKey) {
	if err := signedPost("/relays/deregister", pubKeyB64, priv, nil); err != nil {
		log.Printf("[WARN] Failed to deregister relay: %v", err)
	} else {
		log.Println("[INFO] Relay deregistered from librserver")
	}
}

// fetchRelaysFromServer retrieves live relay multiaddrs from librserver.
func fetchRelaysFromServer() ([]string, error) {
	resp, err := http.Get(serverURL + "/relays")
	if err != nil {
		return nil, fmt.Errorf("fetchRelays: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetchRelays: server returned %d", resp.StatusCode)
	}
	var docs []struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&docs); err != nil {
		return nil, fmt.Errorf("fetchRelays: decode: %w", err)
	}
	var addrs []string
	for _, d := range docs {
		if strings.HasPrefix(d.Address, "/") {
			addrs = append(addrs, strings.TrimSpace(d.Address))
		}
	}
	return addrs, nil
}

func main() {
	// fmt.Println("123")
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatalf("Error loading .env file")
	// }

	// // Fetch values

	// sheetURL := os.Getenv("sheetWebAppURL")
	// //fmt.Println(sheetURL)
	// sheetWebAppURL = sheetURL

	// Create connection manager
	fmt.Println("[DEBUG] Creating connection manager...")
	connMgr, err := connmgr.NewConnManager(100, 400)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create connection manager: %v", err)
	}

	// Load/generate persistent author key for server auth
	serverURL = strings.TrimRight(os.Getenv("SERVER_URL"), "/")
	if serverURL == "" {
		log.Fatal("[ERROR] SERVER_URL environment variable is not set")
	}
	relayPrivKey, err := loadOrGenerateKey()
	if err != nil {
		log.Fatalf("[ERROR] Failed to load relay key: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(relayPrivKey.Public().(ed25519.PublicKey))
	log.Printf("[INFO] Relay public key: %s", pubKeyB64)

	libp2pPrivKey, err := loadOrGenerateLibp2pKey()
	if err != nil {
		log.Fatalf("[ERROR] Failed to load/generate libp2p key: %v", err)
	}
	fmt.Println("[DEBUG] Creating relay host...")

	RelayHost, err = libp2p.New(
		libp2p.Identity(libp2pPrivKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/443/ws"),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionManager(connMgr),
		libp2p.EnableNATService(),
		libp2p.EnableRelayService(),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
	)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create relay host: %v", err)
	}
	RelayHost.Network().Notify(&RelayEvents{})
	relayDomain := os.Getenv("RELAY_DOMAIN")
	if relayDomain == "" {
		log.Fatal("[ERROR] RELAY_DOMAIN environment variable is not set")
	}
	relayMultiaddrFull := fmt.Sprintf("/dns4/%s/tcp/443/wss/p2p/%s", relayDomain, RelayHost.ID().String())

	defer func() {
		fmt.Println("[DEBUG] Shutting down relay...")
		deregisterRelayFromServer(pubKeyB64, relayPrivKey)
		RelayHost.Close()
	}()
	customRelayResources := relay.Resources{
		Limit: &relay.RelayLimit{
			Duration: 30 * time.Minute,
			Data:     1 << 20, // 1MB data limit per stream
		},
		ReservationTTL:         time.Hour,
		MaxReservations:        512,
		MaxCircuits:            64,
		BufferSize:             4096,
		MaxReservationsPerPeer: 10,
		MaxReservationsPerIP:   100, // Increased from the default of 8
		MaxReservationsPerASN:  64,
	}

	// Enable circuit relay service
	fmt.Println("[DEBUG] Enabling circuit relay service...")
	_, err = relay.New(RelayHost, relay.WithResources(customRelayResources))
	if err != nil {
		log.Fatalf("[ERROR] Failed to enable relay service: %v", err)
	}

	fmt.Printf("[INFO] Relay started!\n")
	fmt.Printf("[INFO] Peer ID: %s\n", RelayHost.ID())

	// Print all addresses
	for _, addr := range RelayHost.Addrs() {
		fmt.Printf("[INFO] Relay Address: %s/p2p/%s\n", addr, RelayHost.ID())
	}

	// Register with librserver so clients can discover this relay.
	go func() {
		if err := registerRelayWithServer(relayMultiaddrFull, pubKeyB64, relayPrivKey); err != nil {
			log.Printf("[WARN] Initial registration failed: %v", err)
		}
	}()

	RelayHost.SetStreamHandler("/chat/1.0.0", handleChatStream)
	go func() {
		for {
			mu.RLock()
			fmt.Println("[DEBUG] IDmap:", IDmap)
			mu.RUnlock()
			time.Sleep(30 * time.Second)
		}
	}()

	fmt.Println("[DEBUG] Waiting for interrupt signal...")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("[INFO] Shutting down relay...")
}

func handleChatStream(s network.Stream) {
	fmt.Println("[DEBUG] Incoming chat stream from", s.Conn().RemoteMultiaddr())
	defer s.Close()
	reader := bufio.NewReader(s)
	for {

		var req reqFormat
		buf := make([]byte, 1024*4) // or size based on expected message
		n, err := reader.Read(buf)
		if err != nil {
			fmt.Println("[DEBUG] Error reading from connection at relay:", err)
			return
		}
		buf = bytes.TrimRight(buf, "\x00")

		err = json.Unmarshal(buf[:n], &req)
		if err != nil {
			fmt.Printf("[DEBUG] Error parsing JSON at relay: %v\n", err)
			fmt.Printf("[DEBUG] Received Data: %s\n", string(buf[:n]))
			return
		}

		fmt.Printf("req by user is : %+v \n", req)

		if req.Type == "register" {
			peerID := s.Conn().RemotePeer()
			fmt.Printf("[INFO] Registering peer: %s\n", req.PeerID)
			fmt.Println("[INFO] Registering the peer into relay map")
			mu.Lock()
			IDmap[req.PeerID] = peerID.String()
			mu.Unlock()
		}

		if req.Type == "SendMsg" {
			mu.RLock()
			targetPeerID := IDmap[req.PeerID]
			mu.RUnlock()
			if targetPeerID == "" {
				fmt.Println("[DEBUG]This peer is not on this relay, contacting other relay")
				targetRelayAddr := GetRelayAddr(req.PeerID)

				var forwardReq reqFormat
				forwardReq.Body = req.Body
				forwardReq.ReqParams = req.ReqParams
				forwardReq.PeerID = req.PeerID
				forwardReq.Type = "forward"

				relayMA, err := ma.NewMultiaddr(targetRelayAddr)
				if err != nil {
					fmt.Println("[DEBUG] Failed to parse relay multiaddr:", err)
					return
				}

				TargetRelayInfo, err := peer.AddrInfoFromP2pAddr(relayMA)
				if err != nil {
					fmt.Println("[DEBUG] Failed to parse target relay info:", err)
					return
				}

				err = RelayHost.Connect(context.Background(), *TargetRelayInfo)
				if err != nil {
					fmt.Println("[DEBUG] Failed to connect to target relay:", err)
					return
				}

				forwardStream, err := RelayHost.NewStream(context.Background(), TargetRelayInfo.ID, ChatProtocol)
				if err != nil {
					fmt.Println("[DEBUG] Failed to open stream to target relay:", err)
					return
				}
				defer forwardStream.Close()

				jsonForwardReq, err := json.Marshal(forwardReq)
				if err != nil {
					fmt.Println("[DEBUG] Failed to marshal forward request:", err)
					return
				}

				_, err = forwardStream.Write(append(jsonForwardReq, '\n'))
				if err != nil {
					fmt.Println("[DEBUG] Failed to write forward request to stream:", err)
					return
				}

				buf := make([]byte, 4096)
				respReader := bufio.NewReader(forwardStream)
				_, err = respReader.Read(buf)
				buf = bytes.TrimRight(buf, "\x00")
				var resp respFormat
				resp.Type = "GET"
				resp.Resp = buf
				fmt.Printf("[Debug]Frowarded Resp from relay : %s : %+v \n", TargetRelayInfo.ID.String(), resp)

				if err != nil {
					fmt.Println("[DEBUG] Error reading response from target relay:", err)
					return
				}

				_, err = s.Write(resp.Resp)
				defer s.Close()
				if err != nil {
					fmt.Println("[DEBUG] Error sending back to original sender:", err)
					return
				}

			} else {
				fmt.Println("Target peer ID: ", targetPeerID)
				if RelayHost == nil {
					fmt.Println("[FATAL] RelayHost is nil!")
					return
				}
				relayID := RelayHost.ID()
				fmt.Println("1")
				targetID, err := peer.Decode(targetPeerID)
				fmt.Println("2")
				if err != nil {
					log.Printf("[ERROR] Invalid Peer ID: %v", err)
					s.Write([]byte("invalid peer id"))
					return
				}

				relayBaseAddr, err := ma.NewMultiaddr("/p2p/" + relayID.String())
				if err != nil {
					log.Fatal("relayBaseAddr error:", err)
				}
				circuitAddr, _ := ma.NewMultiaddr("/p2p-circuit")
				targetAddr, _ := ma.NewMultiaddr("/p2p/" + targetID.String())
				fullAddr := relayBaseAddr.Encapsulate(circuitAddr).Encapsulate(targetAddr)
				fmt.Println("[DEBUG]", fullAddr.String())
				addrInfo, err := peer.AddrInfoFromP2pAddr(fullAddr)
				if err != nil {
					log.Printf("Invalid relayed multiaddr: %s", fullAddr)
					s.Write([]byte("bad relayed addr"))
					return
				}

				// Add the relayed address to the peerstore. PeerStore is a mapping in which peer ID is mapped to multiaddr for that peer. This is used whenever we want to open a stream. Once added then we should connect to the peer and open a stream to send message to the relay
				RelayHost.Peerstore().AddAddrs(addrInfo.ID, addrInfo.Addrs, peerstore.PermanentAddrTTL)

				err = RelayHost.Connect(context.Background(), *addrInfo)
				if err != nil {
					log.Printf("[ERROR] Failed to connect to relayed peer: %v", err)
				}

				sendStream, err := RelayHost.NewStream(context.Background(), targetID, ChatProtocol)
				if err != nil {
					fmt.Println("[DEBUG]Error opening stream to target peer")
					fmt.Println(err)
					s.Write([]byte("failed"))
					return
				}
				jsonReqServer, err := json.Marshal(req)
				if err != nil {
					fmt.Println("[DEBUG]Error marshalling the req for server ")
				}
				_, err = sendStream.Write(append(jsonReqServer, '\n'))

				if err != nil {
					fmt.Println("[DEBUG]Error sending messgae despite stream opened")
					return
				}

				buf := make([]byte, 1024*64)
				RespReader := bufio.NewReader(sendStream)
				RespReader.Read(buf)
				buf = bytes.TrimRight(buf, "\x00")
				var resp respFormat
				resp.Type = "GET"
				resp.Resp = buf
				fmt.Printf("[Debug]Resp from %s : %+v \n", targetID.String(), resp)

				jsonResp, err := json.Marshal(resp)
				if err != nil {
					fmt.Println("[DEBUG]Error marshalling the response at relay")
				}
				_ = jsonResp // if required whole jsonResp can be sent but it makes unmarhsalling the response harder for the client
				fmt.Println("[DEBUG]Raw Resp :", string(resp.Resp))
				_, err = s.Write(resp.Resp)
				if err != nil {
					fmt.Println("[DEBUG]Error sending response back")
				}
				defer s.Close()
				defer sendStream.Close()
			}
		}

		if req.Type == "forward" {
			mu.RLock()
			targetPeerID := IDmap[req.PeerID]
			mu.RUnlock()

			if targetPeerID == "" {
				fmt.Println("[DEBUG] Target peer not found in this relay")
				s.Write([]byte("Target peer not found"))
				return
			}

			targetID, err := peer.Decode(targetPeerID)
			if err != nil {
				fmt.Println("[DEBUG] Invalid target peer ID")
				return
			}

			// Build relayed addr
			relayID := RelayHost.ID()
			relayBaseAddr, _ := ma.NewMultiaddr("/p2p/" + relayID.String())
			circuitAddr, _ := ma.NewMultiaddr("/p2p-circuit")
			targetAddr, _ := ma.NewMultiaddr("/p2p/" + targetID.String())
			fullAddr := relayBaseAddr.Encapsulate(circuitAddr).Encapsulate(targetAddr)

			addrInfo, err := peer.AddrInfoFromP2pAddr(fullAddr)
			if err != nil {
				fmt.Println("[DEBUG] Invalid relayed address")
				return
			}

			RelayHost.Peerstore().AddAddrs(addrInfo.ID, addrInfo.Addrs, peerstore.PermanentAddrTTL)

			err = RelayHost.Connect(context.Background(), *addrInfo)
			if err != nil {
				fmt.Println("[DEBUG] Failed to connect to target peer at this relay")
				return
			}

			sendStream, err := RelayHost.NewStream(context.Background(), targetID, ChatProtocol)
			if err != nil {
				fmt.Println("[DEBUG] Failed to open stream to target peer")
				return
			}
			defer sendStream.Close()

			jsonReqServer, err := json.Marshal(req)
			if err != nil {
				fmt.Println("[DEBUG]Error marshalling the req for server ")
			}
			_, err = sendStream.Write(append(jsonReqServer, '\n'))

			if err != nil {
				fmt.Println("[DEBUG]Error sending messgae despite stream opened")
				return
			}
			//s.Write([]byte("Success\n"))

			buf := make([]byte, 1024)
			RespReader := bufio.NewReader(sendStream)
			RespReader.Read(buf)
			buf = bytes.TrimRight(buf, "\x00")
			var resp respFormat
			resp.Type = "GET"
			resp.Resp = buf
			fmt.Printf("[Debug]Resp from %s : %+v \n", targetID.String(), resp)

			jsonResp, err := json.Marshal(resp)
			if err != nil {
				fmt.Println("[DEBUG]Error marshalling the response at relay")
			}
			_ = jsonResp // if required whole jsonResp can be sent but it makes unmarhsalling the response harder for the client
			fmt.Println("[DEBUG]Raw Resp :", string(resp.Resp))
			_, err = s.Write(resp.Resp)
			if err != nil {
				fmt.Println("[DEBUG]Error sending response back")
			}
			defer s.Close()
			defer sendStream.Close()
		}
	}
}

// GetRelayAddr uses XOR distance to pick the best relay for a given peer ID.
func GetRelayAddr(peerID string) string {
	RelayMultiAddrList, err := fetchRelaysFromServer()
	if err != nil {
		fmt.Println("[DEBUG] Error getting relays from server:", err)
		return ""
	}

	var relayList []string
	for _, maddr := range RelayMultiAddrList {
		parts := strings.Split(maddr, "/")
		relayList = append(relayList, parts[len(parts)-1])
	}

	h1 := sha256.New()
	h1.Write([]byte(peerID))
	peerIDhash := hex.EncodeToString(h1.Sum(nil))

	var distmap []RelayDist
	for _, r := range relayList {
		hR := sha256.New()
		hR.Write([]byte(r))
		relayIDhash := hex.EncodeToString(hR.Sum(nil))
		dist := XorHexToBigInt(peerIDhash, relayIDhash)
		distmap = append(distmap, RelayDist{dist: dist, relayID: r})
	}

	sort.Slice(distmap, func(i, j int) bool {
		return distmap[i].dist.Cmp(distmap[j].dist) < 0
	})

	relayIDused := distmap[0].relayID
	for _, maddr := range RelayMultiAddrList {
		parts := strings.Split(maddr, "/")
		if parts[len(parts)-1] == relayIDused {
			return maddr
		}
	}
	return ""
}

func XorHexToBigInt(hex1, hex2 string) *big.Int {
	bytes1, err1 := hex.DecodeString(hex1)
	bytes2, err2 := hex.DecodeString(hex2)
	if err1 != nil || err2 != nil {
		log.Fatalf("Error decoding hex: %v %v", err1, err2)
	}
	if len(bytes1) != len(bytes2) {
		log.Fatalf("Hex strings must be the same length")
	}
	xorBytes := make([]byte, len(bytes1))
	for i := range bytes1 {
		xorBytes[i] = bytes1[i] ^ bytes2[i]
	}
	return new(big.Int).SetBytes(xorBytes)
}
