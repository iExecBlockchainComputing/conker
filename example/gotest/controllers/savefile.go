package controllers

import (
	beego "github.com/beego/beego/v2/server/web"
	"os"
)

type FileController struct {
	beego.Controller
}

func (h *FileController) SaveDataToFile() {
	data := h.GetString("data", "")
	res := new(Res)
	err := os.WriteFile("/data/test.txt", []byte(data), os.ModePerm)
	if err != nil {
		res.Code = 400
		res.Message = err.Error()
		h.Data["json"] = res
		h.ServeJSON()
		return
	}
	res.Code = 200
	res.Message = "save data successful"
	h.Data["json"] = res
	h.ServeJSON()
}

func (h *FileController) ReadSavedData() {
	res := new(Res)
	data, err := os.ReadFile("/data/test.txt")
	if err != nil {
		res.Code = 400
		res.Message = err.Error()
		h.Data["json"] = res
		h.ServeJSON()
		return
	}
	res.Code = 200
	res.Message = "read data successful"
	res.Data = string(data)
	h.Data["json"] = res
	h.ServeJSON()
}
