package aws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	awsKmsSignOperationMessageType     = "DIGEST"
	awsKmsSignOperationSigningAlgorithm = "ECDSA_SHA_256"
)

type Asn1EcPublicKey struct {
	EcPublicKeyInfo Asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type Asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type Asn1EcSig struct {
	R *big.Int
	S *big.Int
}

func GetPublicKeyDerBytesFromKMS(ctx context.Context, svc *kms.KMS, keyId string) ([]byte, error) {
	getPubKeyOutput, err := svc.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get public key from KMS for KeyId=%s", keyId)
	}

	var asn1pubk Asn1EcPublicKey
	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse ASN.1 public key for KeyId=%s", keyId)
	}

	return asn1pubk.PublicKey.Bytes, nil
}

func GetPubKey(ctx context.Context, svc *kms.KMS, keyId string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := GetPublicKeyDerBytesFromKMS(ctx, svc, keyId)
	if err != nil {
		return nil, err
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot construct secp256k1 public key from key bytes")
	}

	return pubKey, nil
}

func SignMessage(ctx context.Context, svc *kms.KMS, keyId string, messageHash [32]byte) ([]byte, error) {
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyId),
		SigningAlgorithm: aws.String(awsKmsSignOperationSigningAlgorithm),
		MessageType:      aws.String(awsKmsSignOperationMessageType),
		Message:          messageHash[:],
	}

	signOutput, err := svc.SignWithContext(ctx, signInput)
	if err != nil {
		return nil, err
	}

	return signOutput.Signature, nil
}
