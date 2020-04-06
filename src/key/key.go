package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

/*func getPrivateKey(email string, keyType certcrypto.KeyType) crypto.PrivateKey {
	keyPath := filepath.Join("xsacert.key")

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Printf("No key found. Generating new key.")

		privateKey, err := generatePrivateKey(keyPath, keyType)
		if err != nil {
			log.Fatalf("Could not generate RSA private account key")
		}

		log.Printf("Saved key to %s", keyPath)
		return privateKey
	}

	privateKey, err := loadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("Could not load RSA private key from file %s: %v", keyPath, err)
	}

	return privateKey
}

func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}*/

func Test() {



}

func Generate() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func SaveToFile(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer file.Close()

	pkcs8, err := rsaToPkcs8(key)
	if err != nil {
		return err
	}

	pem := pkcs8ToPem(pkcs8)

	_, err = file.Write(pem)
	return err
}

func LoadFromFile(filename string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pkcs8 := pemToPkcs8(bytes)
	return pkcs8ToRsa(pkcs8)
}

func rsaToPkcs8(key *rsa.PrivateKey) ([]byte, error) {
	var pkey pkcs8

	pkey.Version = 0
	pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	pkey.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	pkey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	return asn1.Marshal(pkey)
}

func pkcs8ToPem(bytes []byte) []byte {
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   bytes,
	}
	return pem.EncodeToMemory(&block)
}

func pemToPkcs8(bytes []byte) []byte {
	block, _ := pem.Decode(bytes)
	return block.Bytes
}

func pkcs8ToRsa(bytes []byte) (*rsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Expected key to be of type *rsa.PrivateKey.")
	}

	return rsaPrivateKey, nil
}
