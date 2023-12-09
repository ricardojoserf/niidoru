// Source: https://gist.githubusercontent.com/aziza-kasenova/3aea2160cbaebc5a4ba1b9219cba612e/raw/32b3801369ce669b2b1bf89ca84d24f23b487579/AES256.go

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	//"bufio"
)

// GetAESDecrypted decrypts given text in AES 256 CBC
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

// PKCS5UnPadding  pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	
	length := len(src)
	unpadding := int(src[length-1])

	if (unpadding > 16){
		return src
	} else{
		return src[:(length - unpadding)]
	}
}

// GetAESEncrypted encrypts given text in AES 256 CBC
func GetAESEncrypted(plaintext string, key string, iv string) (string, error) {
	var plainTextBlock []byte
	length := len(plaintext)

	if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}

	copy(plainTextBlock, plaintext)
	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(ciphertext)

	return str, nil
}


func GetAESDecrypted_aux(decrypted_string string, key string, iv string) string {
    decrypted, err := GetAESDecrypted(decrypted_string, key, iv)
    if err != nil{
    	fmt.Println("[-] Error decrypting AES value")
    	os.Exit(-1)
    }
    return string(decrypted)
}


/*
func main() {
	key := "N33dl3N33dl3N33dl3N33dl3N33dl333"
	iv := "N33dl3N33dl3N33d"

	for {
			fmt.Print("Value: ")
			input := bufio.NewScanner(os.Stdin)
			input.Scan()
			plainText := input.Text()

			encrypted, err := GetAESEncrypted(plainText, key, iv)
			if err != nil {
				fmt.Println("Error during encryption", err)
			}
			fmt.Print("var ",plainText,"_str string = GetAESDecrypted_aux(\"", encrypted, "\", \"", key, "\", \"", iv ,"\")\n")
			
			//decrypted, err := GetAESDecrypted(encrypted, key, iv)
			//if err != nil {
			//	fmt.Println("Error during decryption", err)
			//}
			//fmt.Println("This is a decrypted:", string(decrypted))
	}
}
*/