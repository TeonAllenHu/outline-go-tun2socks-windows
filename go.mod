module teon.com/outline-go-tun2socks-windows

go 1.20

require github.com/Jigsaw-Code/outline-go-tun2socks v0.0.0

replace github.com/Jigsaw-Code/outline-go-tun2socks => ../outline-go-tun2socks

require github.com/Jigsaw-Code/outline-sdk v0.0.6

require github.com/TeonAllenHu/go-socks5 v0.0.0

replace github.com/TeonAllenHu/go-socks5 => ../go-socks5

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
)
