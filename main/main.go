package main

// #include <stdlib.h>
import "C"
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	syslog "log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Jigsaw-Code/outline-go-tun2socks/outline/shadowsocks"
	"github.com/Jigsaw-Code/outline-go-tun2socks/outline/tun2socks"
	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/network/lwip2transport"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	ss "github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/TeonAllenHu/go-socks5"
	"github.com/TeonAllenHu/go-socks5/statute"
	"github.com/eycorsican/go-tun2socks/common/log"
	"teon.com/outline-go-tun2socks-windows/main/commands"
	"teon.com/outline-go-tun2socks-windows/main/commands/base"
	utf8 "teon.com/outline-go-tun2socks-windows/main/internal"

	_ "github.com/eycorsican/go-tun2socks/common/log/simple"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/dnsfallback"
	"github.com/eycorsican/go-tun2socks/tun"
)

var ipDevice network.IPDevice
var staticPacketListener transport.PacketListener

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
	startTest(60315, "159.203.107.7:443", "chacha20-ietf-poly1305", "r6WCeI6GwYrEQDAq7aEvxQ", "TEST001")
	base.BaseCommand.Long = "A unified platform for anti-censorship."
	base.RegisterCommand(commands.CmdInfo)
	base.Execute()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	sig := <-osSignals
	log.Debugf("Received signal: %v", sig)
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
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
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
				return nil, fmt.Errorf("failed to parse prefix string: %w", err)
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

//export FreeCString
func FreeCString(s *C.char) {
	pointer := unsafe.Pointer(s)
	C.free(pointer)
}

func parseStringPrefix(utf8Str string) ([]byte, error) {
	runes := []rune(utf8Str)
	rawBytes := make([]byte, len(runes))
	for i, r := range runes {
		if (r & 0xFF) != r {
			return nil, fmt.Errorf("character out of range: %d", r)
		}
		rawBytes[i] = byte(r)
	}
	return rawBytes, nil
}

//export StartWithoutTAP
func StartWithoutTAP(port int, addrP, cipherP, secretP, prefixP *C.char) *C.char {
	if ipDevice != nil {
		return nil
	}

	cipher := C.GoString(cipherP)
	secret := C.GoString(secretP)

	cryptoKey, err := ss.NewEncryptionKey(cipher, secret)
	if err != nil {
		return C.CString(err.Error())
	}

	addr := C.GoString(addrP)
	var dialer net.Dialer = net.Dialer{}

	streamDialer, err := ss.NewStreamDialer(&transport.TCPEndpoint{Dialer: dialer, Address: addr}, cryptoKey)
	if err != nil {
		return C.CString(err.Error())
	}

	prefix := C.GoString(prefixP)
	// More about prefix: https://www.reddit.com/r/outlinevpn/wiki/index/prefixing/
	if len(prefix) > 0 {
		prefix, err := parseStringPrefix(prefix)
		if err != nil {
			return C.CString(err.Error())
		}
		streamDialer.SaltGenerator = ss.NewPrefixSaltGenerator(prefix)
	}
	packetListener, err := ss.NewPacketListener(transport.UDPEndpoint{Dialer: dialer, Address: addr}, cryptoKey)
	if err != nil {
		return C.CString(err.Error())
	}
	// TODO Support dnstruncate packet proxy in case the server doesn't support UDP,
	// server connectivity can be tested by `TestConnectivity`.
	packetProxy, err := network.NewPacketProxyFromPacketListener(packetListener)
	if err != nil {
		return C.CString(err.Error())
	}
	ipDevice, err = lwip2transport.ConfigureDevice(streamDialer, packetProxy)
	if err != nil {
		return C.CString(err.Error())
	}
	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(syslog.New(os.Stdout, "socks5: ", syslog.LstdFlags))),
		socks5.WithConnectHandle(handleConnect),
		socks5.WithAssociateHandle(handleAssociate2),
	)

	// Create SOCKS5 proxy on localhost port
	go func() {
		socks5Addr := fmt.Sprintf("127.0.0.1:%d", port)
		if err := server.ListenAndServe("tcp", socks5Addr); err != nil {
			panic(err)
		}
	}()
	return nil
}

func startTest(port int, addr, cipher, secret, prefix string) *C.char {
	if ipDevice != nil {
		return nil
	}

	//cipher := C.GoString(cipherP)
	//secret := C.GoString(secretP)

	cryptoKey, err := ss.NewEncryptionKey(cipher, secret)
	if err != nil {
		return C.CString(err.Error())
	}

	//addr := C.GoString(addrP)
	var dialer net.Dialer = net.Dialer{}

	streamDialer, err := ss.NewStreamDialer(&transport.TCPEndpoint{Dialer: dialer, Address: addr}, cryptoKey)
	if err != nil {
		return C.CString(err.Error())
	}

	//prefix := C.GoString(prefixP)
	// More about prefix: https://www.reddit.com/r/outlinevpn/wiki/index/prefixing/
	if len(prefix) > 0 {
		prefix, err := parseStringPrefix(prefix)
		if err != nil {
			return C.CString(err.Error())
		}
		streamDialer.SaltGenerator = ss.NewPrefixSaltGenerator(prefix)
	}

	packetListener, err := ss.NewPacketListener(transport.UDPEndpoint{Dialer: dialer, Address: addr}, cryptoKey)
	if err != nil {
		return C.CString(err.Error())
	}

	staticPacketListener = packetListener

	// TODO Support dnstruncate packet proxy in case the server doesn't support UDP,
	// server connectivity can be tested by `TestConnectivity`.
	/*
		packetProxy, err := network.NewPacketProxyFromPacketListener(packetListener)
		if err != nil {
			return C.CString(err.Error())
		}

		ipDevice, err = lwip2transport.ConfigureDevice(streamDialer, packetProxy)
		if err != nil {
			return C.CString(err.Error())
		}
	*/
	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(syslog.New(os.Stdout, "socks5: ", syslog.LstdFlags))),
		socks5.WithConnectDial(func(ctx context.Context, addr string) (net.Conn, error) {
			return streamDialer.Dial(ctx, addr)
		}),
		//socks5.WithConnectHandle(handleConnect),
		socks5.WithAssociateHandle(handleAssociate),
	)

	// Create SOCKS5 proxy on localhost port
	go func() {
		socks5Addr := fmt.Sprintf("127.0.0.1:%d", port)
		if err := server.ListenAndServe("tcp", socks5Addr); err != nil {
			panic(err)
		}
	}()
	return nil
}

// handleAssociate is used to handle a connect command
func handleAssociate(ctx context.Context, sf *socks5.Server, writer io.Writer, request *socks5.Request) error {
	// Attempt to connect
	bindLn, err := net.ListenUDP("udp", nil)
	if err != nil {
		if err := socks5.SendReply(writer, statute.RepServerFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}

	log.Infof("client want to associate udp, udp listen at addr: %s", bindLn.LocalAddr())
	// send BND.ADDR and BND.PORT, client used
	if err = socks5.SendReplyWithAddr(writer, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	sf.GoFunc(func() {
		// read from client and write to remote server
		conns := sync.Map{}
		bufPool := sf.GetBuffer()
		defer func() {
			sf.PutBuffer(bufPool)
			bindLn.Close()
			conns.Range(func(key, value any) bool {
				if connTarget, ok := value.(net.PacketConn); !ok {
					log.Errorf("conns has illegal item %v:%v", key, value)
				} else {
					connTarget.Close()
				}
				return true
			})
		}()
		for {
			n, srcAddr, err := bindLn.ReadFromUDP(bufPool[:cap(bufPool)])
			if err != nil {
				if errors.Is(err, io.ErrShortBuffer) {
					continue
				}
				log.Errorf("read from udp error :%v", err)
				return
			}
			pk, err := statute.ParseDatagram(bufPool[:n])
			if err != nil {
				continue
			}
			/*
				// check src addr whether equal requst.DestAddr
				srcEqual := ((request.DestAddr.IP.IsUnspecified()) ||
				 request.DestAddr.IP.Equal(srcAddr.IP)) && (request.DestAddr.Port == 0 || request.DestAddr.Port == srcAddr.Port) //nolint:lll
				if !srcEqual {
					continue
				}*/

			dstAddr, err := net.ResolveUDPAddr("udp", pk.DstAddr.Address())

			if err != nil {
				continue
			}

			connKey := srcAddr.String() + "--" + pk.DstAddr.String()

			if target, ok := conns.Load(connKey); !ok {
				// if the 'connection' doesn't exist, create one and store it
				targetNew, err := staticPacketListener.ListenPacket(ctx)
				if err != nil {
					log.Errorf("connect to %v failed, %v", pk.DstAddr, err)
					// TODO:continue or return Error?
					continue
				}
				conns.Store(connKey, targetNew)
				// read from remote server and write to original client
				sf.GoFunc(func() {
					bufPool := sf.GetBuffer()
					defer func() {
						targetNew.Close()
						conns.Delete(connKey)
						sf.PutBuffer(bufPool)
					}()

					for {
						buf := bufPool[:cap(bufPool)]
						n, remoteAddr, err := targetNew.ReadFrom(buf)
						if err != nil {
							if errors.Is(err, io.EOF) ||
								errors.Is(err, net.ErrClosed) {
								return
							}
							log.Errorf("read data from remote %s failed, %v", remoteAddr.String(), err)
							return
						}
						tmpBufPool := sf.GetBuffer()
						proBuf := tmpBufPool
						proBuf = append(proBuf, pk.Header()...)
						proBuf = append(proBuf, buf[:n]...)
						if _, err := bindLn.WriteTo(proBuf, srcAddr); err != nil {
							sf.PutBuffer(tmpBufPool)
							log.Errorf("write data to client %s failed, %v", srcAddr, err)
							return
						}
						sf.PutBuffer(tmpBufPool)
					}
				})
				if _, err := targetNew.WriteTo(pk.Data, dstAddr); err != nil {
					log.Errorf("write data to remote server %s failed, %v", dstAddr.String(), err)
					return
				}
			} else {
				if _, err := target.(net.PacketConn).WriteTo(pk.Data, dstAddr); err != nil {
					log.Errorf("write data to remote server %s failed, %v", dstAddr.String(), err)
					return
				}
			}
		}
	})

	buf := sf.GetBuffer()
	defer sf.PutBuffer(buf)

	for {
		_, err := request.Reader.Read(buf[:cap(buf)])
		// sf.logger.Errorf("read data from client %s, %d bytesm, err is %+v", request.RemoteAddr.String(), num, err)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

//export Stop
func Stop() *C.char {
	if ipDevice != nil {
		err := ipDevice.Close()
		ipDevice = nil
		return C.CString(err.Error())
	}
	return nil
}
