package main

import "crypto/aes"
import "crypto/cipher"
import "encoding/base64"
import "fmt"
import "os"


// Source (solving some minor mistakes): https://medium.com/insiderengineering/aes-encryption-and-decryption-in-golang-php-and-both-with-full-codes-ceb598a34f41
func GetAESDecrypted(encrypted string, key string, iv string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}


func PKCS5UnPadding(src []byte) []byte {
	
	length := len(src)
	unpadding := int(src[length-1])

	if (unpadding > 16){
		return src
	} else{
		return src[:(length - unpadding)]
	}
}


func GetAESDecrypted_aux(decrypted_string string, key string, iv string) string {
    decrypted, err := GetAESDecrypted(decrypted_string, key, iv)
    if err != nil{
    	fmt.Println("[-] Error decrypting AES value")
    	os.Exit(-1)
    }
    return string(decrypted)
}