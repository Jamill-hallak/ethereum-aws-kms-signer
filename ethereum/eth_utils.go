package ethereum

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func GetAddress(pubKey *ecdsa.PublicKey) common.Address {
	pubBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := crypto.Keccak256Hash(pubBytes[1:]).Bytes() // Exclude the prefix 0x04
	return common.BytesToAddress(hash[12:])
}

func CreateMessageHash(authorizedSigner common.Address, landId uint64, founder common.Address, nonce string) ([32]byte, [32]byte, error) {
	authorizedSignerBytes := authorizedSigner.Bytes()
	landIdBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(landIdBytes[24:], landId)
	founderBytes := founder.Bytes()
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	message := append(authorizedSignerBytes, append(landIdBytes, append(founderBytes, nonceBytes...)...)...)
	messageHash := crypto.Keccak256Hash(message)
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	prefixedMessage := append(prefix, messageHash.Bytes()...)
	ethSignedMessageHash := crypto.Keccak256Hash(prefixedMessage)

	return messageHash, ethSignedMessageHash, nil
}
