package ethereum

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"bytes"
)

func AdjustSignature(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey, ethSignedMessageHash [32]byte) ([]byte, error) {
	secp256k1N := crypto.S256().Params().N
	secp256k1HalfN := new(big.Int).Div(secp256k1N, big.NewInt(2))

	// Adjust S value from signature according to Ethereum standard
	sBigInt := new(big.Int).SetBytes(sBytes)
	if sBigInt.Cmp(secp256k1HalfN) > 0 {
		sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
	}

	// Determine the recovery ID
	v := byte(27)
	for i := byte(0); i < 2; i++ {
		sig := append(append(rBytes, sBytes...), i+27)
		recoveredPub, err := crypto.Ecrecover(ethSignedMessageHash[:], sig)
		if err == nil && bytes.Equal(elliptic.Marshal(crypto.S256(), pubKey.X, pubKey.Y), recoveredPub) {
			v = i + 27
			break
		}
	}

	signature := append(append(rBytes, sBytes...), v)
	return signature, nil
}
