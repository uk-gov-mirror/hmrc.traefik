package streams

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/beeker1121/goque"
	"github.com/containous/traefik/middlewares/audittap/configuration"
	"github.com/containous/traefik/middlewares/audittap/encryption"
	atypes "github.com/containous/traefik/middlewares/audittap/types"
	log "github.com/sirupsen/logrus"
)

const undeliveredMessagePrefix = "DS_EventMissed_AuditFailureResponse : audit item : "

type httpAuditSinkAsync struct {
	cli       *http.Client
	messages  chan atypes.Encoded
	producers []*httpProducerAsync
	q         *goque.Queue
	enc       encryption.Encrypter
}

type auditDescription struct {
	EventID     string `json:"eventId"`
	AuditSource string `json:"auditSource"`
	AuditType   string `json:"auditType"`
}

// NewQueue is a wrapper for calling cony.NewPublisher
var NewQueue = func(queueLocation string) (*goque.Queue, error) {
	return goque.OpenQueue(queueLocation)
}

// NewHTTPSinkAsync returns an AuditSink for sending messages to Datastream service.
// A connection is made to the specified endpoint and a number of Producers
// each backed by a channel are created, ready to send messages.
func NewHTTPSinkAsync(config *configuration.AuditSink, messageChan chan atypes.Encoded) (sink AuditSink, err error) {
	var client = CreateClient()

	producers := make([]*httpProducerAsync, 0)
	q, err := NewQueue(config.DiskStorePath)
	if err != nil {
		return nil, err
	}

	enc, err := encryption.NewEncrypter(config.EncryptSecret)
	if err != nil {
		return nil, err
	}
	for i := 0; i < config.NumProducers; i++ {
		p, _ := newHTTPProducerAsync(client, config.Endpoint, config.ProxyingFor, messageChan, q, enc)
		producers = append(producers, p)
	}

	aas := &httpAuditSinkAsync{cli: client, producers: producers, messages: messageChan, q: q, enc: enc}

	return aas, nil
}

// CreateClient returns an http client which may or maynot be configured with a certficate.
// Certificate can be supplied by exporting the absolute path to the certificate as an environment variable
// called CERTIFICATEPATH
func CreateClient() *http.Client {
	var certPath = os.Getenv("CERTIFICATEPATH")
	var client *http.Client
	var httpClientTimeout = 1 * time.Second

	if len(certPath) > 0 {
		caCert, err := ioutil.ReadFile(certPath)
		if err != nil {
			log.Error("Error Cert Read ", err)
			os.Exit(1)
		} else {
			log.Info("Cert:", caCert[0:20])
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
			Timeout: httpClientTimeout,
		}
		log.Info("HTTP Client timeout: ", client.Timeout.String())
	} else {
		log.Warn("No CERTIFICATEPATH env var; reverting to http client")
		client = &http.Client{
			Timeout: httpClientTimeout,
		} // no certificate specified or cert not found
		log.Info("HTTP Client timeout: ", client.Timeout.String())
	}

	return client
}

func (aas *httpAuditSinkAsync) Audit(encoded atypes.Encoded) error {
	select {
	case aas.messages <- encoded:
	default:
		handleFailedMessage(encoded)
	}
	return nil
}

func (aas *httpAuditSinkAsync) Close() error {
	for _, p := range aas.producers {
		p.stop <- true
	}
	aas.q.Close()
	return nil
}

type httpProducerAsync struct {
	cli         *http.Client
	endpoint    string
	proxyingFor string
	messages    chan atypes.Encoded
	q           *goque.Queue
	stop        chan bool
	enc         encryption.Encrypter
}

func newHTTPProducerAsync(client *http.Client, endpoint string, proxyingFor string, messages chan atypes.Encoded, q *goque.Queue, enc encryption.Encrypter) (*httpProducerAsync, error) {
	stop := make(chan bool)
	producer := &httpProducerAsync{cli: client, endpoint: endpoint, proxyingFor: proxyingFor, messages: messages, q: q, stop: stop, enc: enc}
	go producer.audit()
	go producer.publish()
	return producer, nil
}

func (p *httpProducerAsync) audit() {
	for {
		encoded := <-p.messages
		_, err := p.q.EnqueueObject(encoded)
		if err != nil {
			log.Error("Error enqueueing audit event: ", err)
			handleFailedMessage(encoded)
		}
	}
}

func constructRequest(endpoint string, proxyingFor string, encoded atypes.Encoded) (*http.Request, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(encoded.Bytes))
	if err != nil {
		handleFailedMessage(encoded)
		return nil, err
	}
	request.Header.Set("Content-Length", fmt.Sprintf("%d", encoded.Length()))
	request.Header.Set("User-Agent", proxyingFor)
	return request, nil
}

func sendRequest(cli *http.Client, encoded atypes.Encoded, request *http.Request) {
	log.SetFormatter(&log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyMsg: "message",
		},
	})

	res, err := cli.Do(request)
	if res != nil {
		defer res.Body.Close()
	}

	if err != nil || res.StatusCode > 299 {
		handleFailedMessage(encoded)
		return
	}
	// close the http body before making a new http request: https://golang.cafe/blog/how-to-reuse-http-connections-in-go.html
	if _, err := io.Copy(ioutil.Discard, res.Body); err != nil {
		log.Fatal(err)
	}
}

func (p *httpProducerAsync) publish() {
	for {
		select {
		case <-p.stop:
			return
		default:
			item, err := p.q.Dequeue()
			if err != nil {
				if err == goque.ErrEmpty {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				// now? nothing to see here ... Should only happen if reference to goque.q is "closed"
				log.Error("httpProducerAsync: deque failed")

				continue
			}
			var encoded atypes.Encoded
			if err = item.ToObject(&encoded); err != nil {
				// well, that didn't work
				log.Error("httpProducerAsync: failed to parse item into recognised type")
			}

			select {
			case <-p.stop:
				// we've been asked to stop prior to publication: re-enqueue the audit message in disk queue
				p.q.EnqueueObject(encoded)
				return
			default:
				req, err := constructRequest(p.endpoint, p.proxyingFor, encoded)
				if err != nil {
					log.Error("httpProducerAsync: unable to construct request")
					return
				}
				sendRequest(p.cli, encoded, req)
			}
		}
	}
}

func handleFailedMessage(encoded atypes.Encoded) {
	log.Warn(undeliveredMessagePrefix + string(encoded.Bytes))
}
