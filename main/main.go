package main

// #include <stdlib.h>
import "C"
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Jigsaw-Code/outline-go-tun2socks/outline/shadowsocks"
	"github.com/Jigsaw-Code/outline-go-tun2socks/outline/tun2socks"
	"github.com/eycorsican/go-tun2socks/common/log"
	"teon.com/outline-go-tun2socks-windows/main/commands"
	"teon.com/outline-go-tun2socks-windows/main/commands/base"
	utf8 "teon.com/outline-go-tun2socks-windows/main/internal"

	_ "github.com/eycorsican/go-tun2socks/common/log/simple"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/dnsfallback"
	"github.com/eycorsican/go-tun2socks/tun"
)

// Register a simple logger.

const (
	mtu        = 1500
	udpTimeout = 30 * time.Second
	persistTun = true // Linux: persist the TUN interface after the last open file descriptor is closed.
)

var jsonArgs JsonParams

type JsonParams struct {
	TunAddr string `json:"tunAddr"`
	TunGw   string `json:"tunGw"`
	TunMask string `json:"tunMask"`
	TunName string `json:"tunName"`
	TunDNS  string `json:"tunDNS"`

	ProxyHost     string `json:"proxyHost"`
	ProxyPort     int    `json:"proxyPort"`
	ProxyPassword string `json:"proxyPassword"`
	ProxyCipher   string `json:"proxyCipher"`
	ProxyPrefix   string `json:"proxyPrefix"`

	ProxyConfig string `json:"proxyConfig"`

	LogLevel          string `json:"logLevel"`
	CheckConnectivity bool   `json:"checkConnectivity"`
	DnsFallback       bool   `json:"dnsFallback"`
	Version           bool   `json:"version"`
}

var args struct {
	tunAddr *string
	tunGw   *string
	tunMask *string
	tunName *string
	tunDNS  *string

	// Deprecated: Use proxyConfig instead.
	proxyHost     *string
	proxyPort     *int
	proxyPassword *string
	proxyCipher   *string
	proxyPrefix   *string

	proxyConfig *string

	logLevel          *string
	checkConnectivity *bool
	dnsFallback       *bool
	version           *bool
}

func main() {
	base.BaseCommand.Long = "A unified platform for anti-censorship."
	base.RegisterCommand(commands.CmdInfo)
	base.Execute()
}

//export Start
func Start(jsonString *C.char) {

	input := C.GoString(jsonString)

	// parse json to params object
	err := json.Unmarshal([]byte(input), &jsonArgs)

	if err != nil {
		log.Errorf("json parse fail.")
		return //empty, err
	}

	args.tunAddr = &jsonArgs.TunAddr
	args.tunGw = &jsonArgs.TunGw
	args.tunMask = &jsonArgs.TunMask
	args.tunDNS = &jsonArgs.TunDNS
	args.tunName = &jsonArgs.TunName

	args.proxyHost = &jsonArgs.ProxyHost
	args.proxyPort = &jsonArgs.ProxyPort
	args.proxyPassword = &jsonArgs.ProxyPassword
	args.proxyCipher = &jsonArgs.ProxyCipher
	args.proxyPrefix = &jsonArgs.ProxyPrefix

	args.proxyConfig = &jsonArgs.ProxyConfig

	args.logLevel = &jsonArgs.LogLevel
	args.dnsFallback = &jsonArgs.DnsFallback
	args.checkConnectivity = &jsonArgs.CheckConnectivity
	args.version = &jsonArgs.Version

	setLogLevel(*args.logLevel)

	client, err := newShadowsocksClientFromArgs()
	if err != nil {
		log.Errorf("Failed to construct Shadowsocks client: %v", err)
		return
		//os.Exit(oss.IllegalConfiguration)
	}

	if *args.checkConnectivity {
		connErrCode, err := shadowsocks.CheckConnectivity(client)
		log.Debugf("Connectivity checks error code: %v", connErrCode)
		if err != nil {
			log.Errorf("Failed to perform connectivity checks: %v", err)
		}
		return
		//os.Exit(connErrCode)
	}

	// Open TUN device
	dnsResolvers := strings.Split(*args.tunDNS, ",")
	tunDevice, err := tun.OpenTunDevice(*args.tunName, *args.tunAddr, *args.tunGw, *args.tunMask, dnsResolvers, persistTun)
	if err != nil {
		log.Errorf("Failed to open TUN device: %v", err)
		return
		//os.Exit(oss.SystemMisconfigured)
	}

	// Output packets to TUN device
	core.RegisterOutputFn(tunDevice.Write)

	// Register TCP and UDP connection handlers
	core.RegisterTCPConnHandler(tun2socks.NewTCPHandler(client))
	if *args.dnsFallback {
		// UDP connectivity not supported, fall back to DNS over TCP.
		log.Debugf("Registering DNS fallback UDP handler")
		core.RegisterUDPConnHandler(dnsfallback.NewUDPHandler())
	} else {
		core.RegisterUDPConnHandler(tun2socks.NewUDPHandler(client, udpTimeout))
	}

	// Configure LWIP stack to receive input data from the TUN device
	lwipWriter := core.NewLWIPStack()
	go func() {
		_, err := io.CopyBuffer(lwipWriter, tunDevice, make([]byte, mtu))
		if err != nil {
			log.Errorf("Failed to write data to network stack: %v", err)
			return
			//os.Exit(oss.Unexpected)
		}
	}()

	log.Infof("tun2socks running...")

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGHUP)
	sig := <-osSignals
	log.Debugf("Received signal: %v", sig)
}

func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		log.SetLevel(log.DEBUG)
	case "info":
		log.SetLevel(log.INFO)
	case "warn":
		log.SetLevel(log.WARN)
	case "error":
		log.SetLevel(log.ERROR)
	case "none":
		log.SetLevel(log.NONE)
	default:
		log.SetLevel(log.INFO)
	}
}

// newShadowsocksClientFromArgs creates a new shadowsocks.Client instance
// from the global CLI argument object args.
func newShadowsocksClientFromArgs() (*shadowsocks.Client, error) {
	if jsonConfig := *args.proxyConfig; len(jsonConfig) > 0 {
		return shadowsocks.NewClientFromJSON(jsonConfig)
	} else {
		// legacy raw flags
		config := shadowsocks.Config{
			Host:       *args.proxyHost,
			Port:       *args.proxyPort,
			CipherName: *args.proxyCipher,
			Password:   *args.proxyPassword,
		}
		if prefixStr := *args.proxyPrefix; len(prefixStr) > 0 {
			if p, err := utf8.DecodeUTF8CodepointsToRawBytes(prefixStr); err != nil {
				return nil, fmt.Errorf("Failed to parse prefix string: %w", err)
			} else {
				config.Prefix = p
			}
		}
		return shadowsocks.NewClient(&config)
	}
}

type AccessKeyParseResult struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Cipher   string `json:"cipher"`
	Password string `json:"passowrd"`
}

//export ParseAccessKey
func ParseAccessKey(accessKey *C.char) *C.char {
	input := C.GoString(accessKey)
	accessKeyURL, err := url.Parse(input)
	if err != nil {
		fmt.Println("failed to parse access key: %w", err)
		return C.CString(fmt.Sprintf("Error: %v", err))
	}
	var portString string
	var host string
	// Host is a <host>:<port> string
	host, portString, err = net.SplitHostPort(accessKeyURL.Host)
	if err != nil {
		fmt.Println("failed to parse endpoint address: %w", err)
		return C.CString(fmt.Sprintf("Error: %v", err))
	}
	cipherInfoBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(accessKeyURL.User.String())
	if err != nil {
		fmt.Println("failed to decode cipher info [%w]: %w", accessKeyURL.User.String(), err)
		return C.CString(fmt.Sprintf("Error: %v", err))
	}
	cipherName, secret, found := strings.Cut(string(cipherInfoBytes), ":")
	if !found {
		return C.CString("invalid cipher info: no ':' separator")
	}

	accessKeyParseResult := AccessKeyParseResult{
		Host:     host,
		Port:     portString,
		Cipher:   cipherName,
		Password: secret,
	}

	// 序列化成JSON
	jsonData, err := json.Marshal(accessKeyParseResult)
	if err != nil {
		return C.CString(fmt.Sprintf("Error: %v", err))
	}
	return C.CString(string(jsonData))
}

// FreeString
func FreeCString(s *C.char) {
	pointer := unsafe.Pointer(s)
	C.free(pointer)
}
