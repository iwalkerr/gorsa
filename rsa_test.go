package gorsa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"testing"
)

const (
	privateKeyPath = "privateKey.pem"
	publicKeyPath  = "publicKey.pem"
)

type TestData struct {
	Id       int
	Token    string
	Username string
	Keys     []Keyss
}

type Keyss struct {
	Name    string
	Price   float64
	Content string
	Pic     string
	Num     int
}

func TestRSA(t *testing.T) {
	_ = RsaGenKey(1024, privateKeyPath, publicKeyPath)

	var kList []Keyss
	for i := 0; i < 50; i++ {
		kList = append(kList, Keyss{
			Name:    "zhagnsandd" + strconv.Itoa(i+1),
			Price:   323.12,
			Content: "dfdsfsd 我的",
			Pic:     "http://weere.32432.com/3e333434.png",
			Num:     100,
		})
	}

	td := TestData{
		Id:       1000,
		Token:    "12121j12j1j23juu23h22h323h22bb",
		Username: "张三",
		Keys:     kList,
	}

	bytes, _ := json.Marshal(td)
	cipherText, err := RsaEncryptBlock(bytes, publicKeyPath)
	if err != nil {
		log.Println("获取公钥失败,err=", err.Error())
		return
	}

	encodeString := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println(encodeString)

	decodeBytes, _ := base64.StdEncoding.DecodeString(encodeString)
	plainText, err := RsaDecryptBlock(decodeBytes, privateKeyPath)
	if err != nil {
		log.Println("私钥解密失败,err:", err.Error())
		return
	}

	var tt TestData
	_ = json.Unmarshal(plainText, &tt)
	fmt.Printf("%+v\n", tt)
}
