package controllers

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/go-sql-driver/mysql"
	"io/ioutil"
	"os"
	"path"
	"time"
)

type DataBase struct {
	UserId     string     `json:"userId,omitempty"`
	Role       string     `json:"role,omitempty"`
	DbName     string     `json:"dbName,omitempty"`
	DbAddress  string     `json:"dbAddress,omitempty"`
	DbUsername string     `json:"dbUserName,omitempty"`
	DbPassword string     `json:"DbPassword,omitempty"`
	DbCaCert   string     `json:"dbCaCert,omitempty"`
	Version    int64      `json:"version,omitempty"`
	CreateTime *time.Time `json:"createTime,omitempty"`
	UpdateTime *time.Time `json:"updateTime,omitempty"`
}

type DBController struct {
	beego.Controller
}

func (h *DBController) GetDataFromDb() {
	res := new(Res)
	userId := os.Getenv("userId")
	info, err := ioutil.ReadFile(path.Join("/secret", userId+"-db.json"))
	if err != nil {
		res.Code = 400
		res.Message = err.Error()
		h.Data["json"] = res
		h.ServeJSON()
		return
	}

	dbInfo := new(DataBase)
	err = json.Unmarshal(info, dbInfo)
	if err != nil {
		res.Code = 400
		res.Message = err.Error()
		h.Data["json"] = res
		h.ServeJSON()
		return
	}
	//data, err := GetData(dbInfo.DbName, dbInfo.DbUsername, dbInfo.DbPassword, dbInfo.DbAddress, dbInfo.DbCaCert)
	//if err != nil {
	//	res.Code = 400
	//	res.Message = err.Error()
	//	h.Data["json"] = res
	//	h.ServeJSON()
	//	return
	//}

	res.Code = 200
	res.Message = "get secret successful"
	res.Data = dbInfo
	h.Data["json"] = res
	h.ServeJSON()
}

func GetData(dbName, dbUser, dbPasswd, dbAddress, CaCert string) (data interface{}, err error) {
	dbTns := fmt.Sprintf("tcp(%s)", dbAddress)
	dbURL := fmt.Sprintf("%s:%s@%s/", dbUser, dbPasswd, dbTns)

	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM([]byte(CaCert)); !ok {
		return nil, fmt.Errorf("add Ca cert failed")
	}

	err = mysql.RegisterTLSConfig("custom", &tls.Config{
		RootCAs: rootCertPool,
		//Certificates: clientCert,
	})
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s%s%s", dbURL, dbName, "?allowNativePasswords=true&tls=custom"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	rows, err := db.Query("SELECT id, name FROM user")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rowdatas := make(map[string]string)
	for rows.Next() {
		var id string
		var name string
		err := rows.Scan(&id, &name)
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("ID: %s, Name: %s\n", id, name)
		rowdatas[id] = name
	}
	return rowdatas, nil
}
