package main

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"your_module/aws"
	"your_module/ethereum"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	keyID := os.Getenv("AWS_KMS_KEY_ID")
	if keyID == "" {
		log.Fatalf("AWS_KMS_KEY_ID not set in .env file")
	}

	svc := aws.NewKMSClient()

	pubKey, err := aws.GetPubKey(context.Background(), svc, keyID)
	if err != nil {
		fmt.Println("Error retrieving public key:", err)
		return
	}

	address := ethereum.GetAddress(pubKey)
	fmt.Println("Authorized Signer Address:", address.Hex())

	// Define the parameters
	authorizedSigner := address
	landId := uint64(12)
	founder := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	nonce := "04973370d5bca7584e204448ecf9a6bf820ef92ce7330fcc00000190f91b68ae"

	// Generate message hashes
	messageHash, ethSignedMessageHash, err := ethereum.CreateMessageHash(authorizedSigner, landId, founder, nonce)
	if err != nil {
		fmt.Println("Error creating message hash:", err)
		return
	}

	fmt.Printf("Message Hash: %s\n", messageHash.Hex())
	fmt.Printf("EthSignedMessage Hash: %s\n", ethSignedMessageHash.Hex())

	// Sign the Ethereum signed message hash
	signatureDER, err := aws.SignMessage(context.Background(), svc, keyID, ethSignedMessageHash)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	fmt.Printf("Signature (DER): %s\n", hex.EncodeToString(signatureDER))

	var sigAsn1 aws.Asn1EcSig
	_, err = asn1.Unmarshal(signatureDER, &sigAsn1)
	if err != nil {
		fmt.Println("Error unmarshalling signature:", err)
		return
	}

	rBytes, sBytes := sigAsn1.R.Bytes(), sigAsn1.S.Bytes()
	fmt.Printf("r: %s\n", hex.EncodeToString(rBytes))
	fmt.Printf("s: %s\n", hex.EncodeToString(sBytes))

	signature, err := ethereum.AdjustSignature(rBytes, sBytes, pubKey, ethSignedMessageHash)
	if err != nil {
		fmt.Println("Error adjusting signature:", err)
		return
	}

	fmt.Printf("Signature: 0x%s\n", hex.EncodeToString(signature))
}
