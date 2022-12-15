package commands

import (
	"fmt"

	"teon.com/outline-go-tun2socks-windows/main/commands/base"
)

// CmdVersion prints V2Ray Versions
var CmdInfo = &base.Command{
	UsageLine: "{{.Exec}} info",
	Short:     "print info",
	Long: `Prints the information for root-Go.
`,
	Run: executeInfo,
}

func executeInfo(cmd *base.Command, args []string) {
	fmt.Println("nthLink was started in 2016 as a project by a group of experienced software and information security engineers to support human rights lawyers to obtain censored information and to express their perspectives to the outside world.\n\nOur development team excels in both the sophistication of censorship circumvention technology and the reliability of the service. With years of experience in this specialty area, we provide the users in targeted geographies simple, safe, and reliable access to otherwise censored information.")
}
