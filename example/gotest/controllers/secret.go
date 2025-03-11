package controllers

import (
	beego "github.com/beego/beego/v2/server/web"
	"io/ioutil"
	"os"
	"path"
)

type SecretController struct {
	beego.Controller
}
type Res struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (h *SecretController) GetSecret() {
	res := new(Res)
	userId := os.Getenv("userId")
	info, err := ioutil.ReadFile(path.Join("/secret", userId+".json"))
	if err != nil {
		res.Code = 400
		res.Message = err.Error()
	} else {
		res.Code = 200
		res.Message = "get secret successful"
		res.Data = string(info)
	}

	h.Data["json"] = res
	h.ServeJSON()
}
