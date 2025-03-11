package main

import (
	beego "github.com/beego/beego/v2/server/web"
	"os"
	_ "socserver/routers"
)

func main() {
	httpsCert := os.Getenv("httpsCert")
	httpsKey := os.Getenv("httpsKey")

	if httpsKey != "" && httpsCert != "" {
		beego.BConfig.Listen.HTTPSCertFile = httpsCert
		beego.BConfig.Listen.HTTPSKeyFile = httpsKey
		beego.BConfig.Listen.EnableHTTPS = true
	}
	beego.Run()
}
