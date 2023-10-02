package log

import (
	"github.com/TeonAllenHu/go-socks5"
	"github.com/eycorsican/go-tun2socks/common/log"
)

type Socks5Logger struct {
	socks5.Logger
}

func (sf Socks5Logger) Errorf(format string, args ...interface{}) {
	log.Errorf("[E]: "+format, args...)
}
