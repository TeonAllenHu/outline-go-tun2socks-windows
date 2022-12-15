package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"teon.com/outline-go-tun2socks-windows/main/commands"
	"teon.com/outline-go-tun2socks-windows/main/commands/base"

	oss "github.com/Jigsaw-Code/outline-go-tun2socks/outline/shadowsocks"
	"github.com/Jigsaw-Code/outline-go-tun2socks/shadowsocks"
	"github.com/eycorsican/go-tun2socks/common/log"
	_ "github.com/eycorsican/go-tun2socks/common/log/simple" // Register a simple logger.
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/dnsfallback"
	"github.com/eycorsican/go-tun2socks/tun"
)

const (
	mtu        = 1500
	udpTimeout = 30 * time.Second
	persistTun = true // Linux: persist the TUN interface after the last open file descriptor is closed.
)

var jsonArgs JsonParams

type JsonParams struct {
	TunAddr           string `json:"tunAddr"`
	TunGw             string `json:"tunGw"`
	TunMask           string `json:"tunMask"`
	TunName           string `json:"tunName"`
	TunDNS            string `json:"tunDNS"`
	ProxyHost         string `json:"proxyHost"`
	ProxyPort         int    `json:"proxyPort"`
	ProxyPassword     string `json:"proxyPassword"`
	ProxyCipher       string `json:"proxyCipher"`
	ProxyPrefix       string `json:"proxyPrefix"`
	LogLevel          string `json:"logLevel"`
	CheckConnectivity bool   `json:"checkConnectivity"`
	DnsFallback       bool   `json:"dnsFallback"`
	Version           bool   `json:"version"`
}

var args struct {
	tunAddr           *string
	tunGw             *string
	tunMask           *string
	tunName           *string
	tunDNS            *string
	proxyHost         *string
	proxyPort         *int
	proxyPassword     *string
	proxyCipher       *string
	proxyPrefix       *string
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
	args.logLevel = &jsonArgs.LogLevel
	args.dnsFallback = &jsonArgs.DnsFallback
	args.checkConnectivity = &jsonArgs.CheckConnectivity
	args.version = &jsonArgs.Version
	/*
		if *args.version {
			fmt.Println(version)
			os.Exit(0)
		}
	*/
	setLogLevel(*args.logLevel)

	// Validate proxy flags
	if *args.proxyHost == "" {
		log.Errorf("Must provide a Shadowsocks proxy host name or IP address")
		return
		//os.Exit(oss.IllegalConfiguration)
	} else if *args.proxyPort <= 0 || *args.proxyPort > 65535 {
		log.Errorf("Must provide a valid Shadowsocks proxy port [1:65535]")
		return
		//os.Exit(oss.IllegalConfiguration)
	} else if *args.proxyPassword == "" {
		log.Errorf("Must provide a Shadowsocks proxy password")
		return
		//os.Exit(oss.IllegalConfiguration)
	} else if *args.proxyCipher == "" {
		log.Errorf("Must provide a Shadowsocks proxy encryption cipher")
		return
		//os.Exit(oss.IllegalConfiguration)
	}

	config := oss.Config{
		Host:       *args.proxyHost,
		Port:       *args.proxyPort,
		Password:   *args.proxyPassword,
		CipherName: *args.proxyCipher,
	}

	// The prefix is an 8-bit-clean byte sequence, stored in the codepoint
	// values of a unicode string, which arrives here encoded in UTF-8.
	prefixRunes := []rune(*args.proxyPrefix)
	config.Prefix = make([]byte, len(prefixRunes))
	for i, r := range prefixRunes {
		if (r & 0xFF) != r {
			log.Errorf("Character out of range: %r", r)
			return
			//os.Exit(oss.IllegalConfiguration)
		}
		config.Prefix[i] = byte(r)
	}

	client, err := oss.NewClient(&config)
	if err != nil {
		log.Errorf("Failed to construct Shadowsocks client: %v", err)
		return
		//os.Exit(oss.IllegalConfiguration)
	}

	if *args.checkConnectivity {
		connErrCode, err := oss.CheckConnectivity(client)
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
	core.RegisterTCPConnHandler(shadowsocks.NewTCPHandler(client))
	if *args.dnsFallback {
		// UDP connectivity not supported, fall back to DNS over TCP.
		log.Debugf("Registering DNS fallback UDP handler")
		core.RegisterUDPConnHandler(dnsfallback.NewUDPHandler())
	} else {
		core.RegisterUDPConnHandler(shadowsocks.NewUDPHandler(client, udpTimeout))
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
