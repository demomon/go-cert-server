package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lizrice/secure-connections/utils"
	"io/ioutil"
	"net/http"
)

func main() {
	certsFolder := flag.String("cf", "/", "Location of the folder containing TLS cert.pem and key.pem files")
	caFolder := flag.String("caf", "/", "Location of the folder containing TLS cert.pem and key.pem files of the CA")
	flag.Parse()

	server := getServer(*caFolder, *certsFolder)
	http.HandleFunc("/", myHandler)
	server.ListenAndServeTLS("", "")
}

func myHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Handling request")
	w.Write([]byte("Hello World"))
}

func getServer(caFolder string, certsFolder string) *http.Server {
	data, _ := ioutil.ReadFile(caFolder + "/minica.pem")
	cp, _ := x509.SystemCertPool()
	cp.AppendCertsFromPEM(data)

	tls := &tls.Config{
		ClientCAs:             cp,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		GetCertificate:        utils.CertReqFunc(certsFolder+"/cert.pem", certsFolder+"/key.pem"),
		VerifyPeerCertificate: utils.CertificateChains,
	}

	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tls,
	}

	//server := &http.Server {
	//	Addr: ":8080",
	//}
	return server
}
