package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"

	"github.com/gliderlabs/logspout/adapters/raw"
	"github.com/gliderlabs/logspout/router"
)

func init() {
	router.AdapterTransports.Register(new(tlsTransport), "tls")
	// convenience adapters around raw adapter
	router.AdapterFactories.Register(rawTLSAdapter, "tls")
}

func rawTLSAdapter(route *router.Route) (router.LogAdapter, error) {
	route.Adapter = "raw+tls"
	return raw.NewRawAdapter(route)
}

type tlsTransport int

func getTlsClientCerts(options map[string]string) ([]tls.Certificate, error) {
	certPath, certOk := options["tls.certificate"]
	keyPath, keyOk := options["tls.key"]
	var certs []tls.Certificate

	if !certOk || !keyOk {
		return certs, nil
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return certs, err
	}

	return []tls.Certificate{cert}, nil
}

func getRootCAs(options map[string]string) (*x509.CertPool, error) {
	caPath, ok := options["tls.ca_pem"]
	if !ok {
		return nil, nil
	}

	caPool := x509.NewCertPool()

	pem, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	ok = caPool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, errors.New("error parsing CA pem: " + caPath)
	}

	return caPool, nil
}

func getTlsConfig(options map[string]string) (*tls.Config, error) {
	certs, err := getTlsClientCerts(options)
	if err != nil {
		return nil, err
	}

	CAs, err := getRootCAs(options)
	if err != nil {
		return nil, err
	}

	conf := &tls.Config{Certificates: certs, RootCAs: CAs}
	return conf, nil
}

func (t *tlsTransport) Dial(addr string, options map[string]string) (net.Conn, error) {
	conf, err := getTlsConfig(options)
	if err != nil {
		return nil, err
	}

	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
