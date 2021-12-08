package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

type Node struct {
	publicKey  rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func newNode() *Node {
	n := Node{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	n.privateKey = privateKey
	n.publicKey = privateKey.PublicKey
	return &n
}

func (n *Node) SendMessage(message string, receiver rsa.PublicKey) ([]byte, []byte) {

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&receiver,
		[]byte(message),
		nil)

	if err != nil {
		panic(err)
	}

	signature := signMessage(message, n.privateKey)

	return encryptedBytes, signature
}

func signMessage(message string, privateKey *rsa.PrivateKey) []byte {
	msgHash := sha256.New()
	msgHash.Write([]byte(message))
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	return signature
}

func (n *Node) ReadMessage(encryptedMessage []byte) []byte {
	decryptedBytes, err := n.privateKey.Decrypt(nil, encryptedMessage, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	return decryptedBytes
}

func (n *Node) CheckSignature(message []byte, sender *Node, signature []byte) bool {

	messageHash := sha256.New()
	messageHash.Write(message)
	messageHashSum := messageHash.Sum(nil)

	err := rsa.VerifyPSS(&sender.publicKey, crypto.SHA256, messageHashSum, signature, nil)
	if err != nil {
		return false
	}

	return true
}

func main() {
	var sender *Node = newNode()
	var receiver *Node = newNode()

	var message, signature []byte = sender.SendMessage("Another commit?!", receiver.publicKey)

	var receivedMessage []byte = receiver.ReadMessage(message)

	fmt.Println(string(receivedMessage))

	if receiver.CheckSignature(receivedMessage, sender, signature) {
		fmt.Println("Signature accepted!")
	} else {
		fmt.Println("Signature is falsificated!")
	}
}
