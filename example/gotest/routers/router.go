package routers

import (
	beego "github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/filter/cors"
	_ "log"
	"socserver/controllers"
)

func init() {
	beego.InsertFilter("*", beego.BeforeRouter, cors.Allow(&cors.Options{
		AllowAllOrigins: true,
		AllowMethods: []string{"*"},
		AllowHeaders: []string{"*", "Authorization"},
		ExposeHeaders: []string{"Content-Length"},
		AllowCredentials: true,
	}))

	//user
	//beego.InsertFilter("/user/v1/*", beego.BeforeExec, authfilter)
	ns_pub := beego.NewNamespace("/api/v1",
		beego.NSRouter("/getsecret", &controllers.SecretController{}, "get:GetSecret"),
		beego.NSRouter("/getdata", &controllers.DBController{}, "get:GetDataFromDb"),
		beego.NSRouter("/file/savedata", &controllers.FileController{}, "get:SaveDataToFile"),
		beego.NSRouter("/file/readdata", &controllers.FileController{}, "get:ReadSavedData"),
	)
	beego.AddNamespace(ns_pub)
}
