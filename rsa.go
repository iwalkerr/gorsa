package gorsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// 生成公钥与私钥
func RsaGenKey(bits int, privatePath, pubulicPath string) error {
	// 1. 生产私钥文件
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	// 2. MarshalPKCS1PrivateKey将rsa私钥序列化为ASN.1 PKCS#1 DER编码
	derPrivateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3. Block代表PEM编码的结构, 对其进行设置
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPrivateStream,
	}
	// 4. 编码私钥, 写入文件
	if err := writeFile(&block, privatePath); err != nil {
		return err
	}

	// 1. 生成公钥文件
	publicKey := privateKey.PublicKey
	derPublicStream := x509.MarshalPKCS1PublicKey(&publicKey)
	// 2. Block代表PEM编码的结构, 对其进行设置
	block = pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPublicStream,
	}
	// 3. 编码公钥, 写入文件
	return writeFile(&block, pubulicPath)
}

/**
 * 私钥解密-分段
 */
func RsaDecryptBlock(src []byte, filename string) (bytesDecrypt []byte, err error) {
	// 从数据中解析出pem块
	block := readFile(filename)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	keySize := privateKey.Size()
	srcSize := len(src)
	log.Println("密钥长度：", keySize, "\t密文长度：\t", srcSize)

	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 解密一部分
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesDecrypt = buffer.Bytes()
	return
}

/**
 * 公钥加密-分段
 */
func RsaEncryptBlock(src []byte, filename string) (bytesEncrypt []byte, err error) {
	// 从数据中找出pem格式的块
	block := readFile(filename)
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return
	}
	keySize, srcSize := publicKey.Size(), len(src)
	log.Println("密钥长度：", keySize, "\t明文长度：\t", srcSize)

	//单次加密的长度需要减掉padding的长度，PKCS1为11
	offSet, once := 0, keySize-11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 加密一部分
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, src[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesEncrypt = buffer.Bytes()
	return
}

// 根据文件名读出内容
func readFile(filename string) *pem.Block {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	_, _ = file.Read(buf)

	// 从数据中找出pem格式的块
	block, _ := pem.Decode(buf)
	return block
}

// 数据写入文件
func writeFile(block *pem.Block, filePath string) error {
	// 1. 创建文件
	createFile, err := os.Create(filePath)
	if createFile != nil {
		defer createFile.Close()
	}
	if err != nil {
		return err
	}

	// 2. 使用pem编码, 并将数据写入文件中
	return pem.Encode(createFile, block)
}
