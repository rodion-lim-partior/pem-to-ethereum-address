package main

import (
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	crypto "github.com/ethereum/go-ethereum/crypto"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func main() {
	if len(os.Args) != 2 {
		panic("Please specify a pem file to read")
	}
	pemData, err := os.ReadFile(os.Args[1]) // just pass the file name, e.g. publicKey.pem
	if err != nil {
		fmt.Print(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}
	var pki publicKeyInfo
	asn1.Unmarshal(block.Bytes, &pki)
	asn1Data := pki.PublicKey.RightAlign()
	_, x, y := asn1Data[0], asn1Data[1:33], asn1Data[33:]
	fmt.Println("x and y : ", hex.EncodeToString(x), hex.EncodeToString(y))
	x_big := new(big.Int)
	x_big.SetBytes(x)
	y_big := new(big.Int)
	y_big.SetBytes(y)
	pubkey := ecdsa.PublicKey{Curve: crypto.S256(), X: x_big, Y: y_big}
	address := crypto.PubkeyToAddress(pubkey)
	isOnCurve := crypto.S256().IsOnCurve(pubkey.X, pubkey.Y)
	fmt.Println("Is the point on curve ? ", isOnCurve)
	fmt.Println("address: ", address)
}
