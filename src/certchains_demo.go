package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	CertificatesPath  = "D:/demo/src/cert/conf"
	IntermediatesCert = "intermediates"
	RootCert          = "root"
	EndUserCert       = "end-user"
)

func main() {

	interDirArray, err := ioutil.ReadDir(filepath.Join(CertificatesPath, IntermediatesCert))
	if err != nil {
		fmt.Println("Read cert dir failed, err:", err)
		return
	}

	for _, interFile := range interDirArray {
		pool := x509.NewCertPool()

		interCertBytes, err := ioutil.ReadFile(filepath.Join(CertificatesPath, IntermediatesCert, interFile.Name()))
		if err != nil {
			fmt.Println("Read intermediates cert file failed, err:", err)
			return
		}

		block, interCertBytes := pem.Decode(interCertBytes)
		if block == nil {
			continue
		}

		interCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		rootDirArray, err := ioutil.ReadDir(filepath.Join(CertificatesPath, RootCert))
		if err != nil {
			fmt.Println(err)
			continue
		}

		for _, rootFile := range rootDirArray {
			poolDemo := x509.NewCertPool()

			rootCertBytes, err := ioutil.ReadFile(filepath.Join(CertificatesPath, RootCert, rootFile.Name()))
			if err != nil {
				fmt.Println("Read root cert file failed, err:", err)
				continue
			}

			poolDemo.AppendCertsFromPEM(rootCertBytes)

			opt := x509.VerifyOptions{
				Roots:     poolDemo,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			if _, err = interCert.Verify(opt); err != nil {
				fmt.Println("Cert verify file failed, err:", err)
				continue
			}

			pool.AppendCertsFromPEM(rootCertBytes)
			pool.AppendCertsFromPEM(interCertBytes)

			if err = ioutil.WriteFile(filepath.Join(CertificatesPath, "cert_relation.conf"), []byte(rootFile.Name()+" -> "+interFile.Name()), os.ModeAppend); err != nil {
				continue
			}

			fmt.Println(rootFile.Name(), " -> ", interFile.Name())
		}
	}
}
