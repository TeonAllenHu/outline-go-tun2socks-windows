package main

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

type AccessKeyParseResult struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Cipher   string `json:"cipher"`
	Password string `json:"passowrd"`
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
