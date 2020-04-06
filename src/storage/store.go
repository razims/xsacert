package storage

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/kennygrant/sanitize"
	"github.com/razims/xsacert/key"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

var (
	storeageDir = ".xsacert"
)

func getFilename(name string, extension string) string {
	if _, err := os.Stat(storeageDir); os.IsNotExist(err) {
		os.Mkdir(storeageDir, 0755)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	return filepath.Join(cwd, storeageDir, fmt.Sprintf("%s.%s", sanitize.Path(name), sanitize.Path(extension)))
}

func saveFile(filename string, bytes []byte) error {
	file, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer file.Close()

	file.Write(bytes)

	return nil
}

func saveCertFile(filename string, bytes []byte) error {
	certOut, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer certOut.Close()

	pemKey, _ := pem.Decode(bytes)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return err
	}

	return nil
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func SetDomainPrivateKey(domain string, privateKey []byte) error {
	filename := getFilename(domain, "key")

	pemKey, _ := pem.Decode(privateKey)

	rsaKey, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   bytes,
	}

	file, _ := os.Create(filename)

	defer file.Close()
	pem.Encode(file, block)

	return nil
}

func SetDomainCertificate(domain string, certificate []byte) error {
	filename := getFilename(domain, "crt")

	return saveCertFile(filename, certificate)
}

func SetDomainIssuerCertificate(domain string, certificate []byte) error {
	filename := getFilename(domain, "issuer.crt")

	return saveCertFile(filename, certificate)
}

func GetUserPrivateKey(email string) (crypto.PrivateKey, error) {
	filename := getFilename(email, "user-private.key")
	var privateKey *rsa.PrivateKey

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("No key found. Generating new key.")
		privateKey, err = key.Generate()
		if err != nil {
			log.Fatalf("Could not generate RSA private account key")
		}

		err = key.SaveToFile(filename, privateKey)
		if err != nil {
			log.Fatalf("Could not save RSA private account key")
		}
	} else {
		return key.LoadFromFile(filename)
	}

	return nil, errors.New("Could not access RSA private account key file")
}

func CreateFullChainCertificate(domain string) error {
	format := `%s
%s
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
`
	domainCertificate, err := ioutil.ReadFile(getFilename(domain, "crt"))
	if err != nil {
		log.Fatal(err)
	}

	issuerCertificate, err := ioutil.ReadFile(getFilename(domain, "issuer.crt"))
	if err != nil {
		log.Fatal(err)
	}

	filename := getFilename(domain, "full.crt")

	return saveFile(filename, []byte(fmt.Sprintf(format, domainCertificate, issuerCertificate)))
}
