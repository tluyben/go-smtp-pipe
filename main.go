package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)




type FullObj struct {
	User     string    `json:"user"`
	Password string    `json:"password"`
	Email    EmailData `json:"email"`
}

var (
	pipeProgram  string
	cer          string
	key          string
	ca           string
	cca          bool
	name         string
	insecure     bool
	aia          bool
	resendSend   bool
	refreshKeys  int
	port         int
	host         string
	enc          tls.Config
	serverPool   *ServerPool
)

func init() {
	flag.StringVar(&pipeProgram, "pipe", "", "Save the result in a random file and pass the filename to the shell program (optional)")
	flag.StringVar(&host, "host", "", "SMTP host")
	flag.IntVar(&port, "port", 25, "SMTP port")
	flag.StringVar(&cer, "cer", "", "Path to certificate (optional)")
	flag.StringVar(&key, "key", "", "Path to key (optional)")
	flag.StringVar(&ca, "ca", "", "Path to ca certificates (optional)")
	flag.StringVar(&name, "server", "", "SMTP server name (optional)")
	flag.BoolVar(&insecure, "insecure", false, "Force run the server in insecure mode (optional)")
	flag.BoolVar(&cca, "cca", false, "Request client certificate (optional)")
	flag.BoolVar(&aia, "aia", false, "Allow insecure auth (optional)")
	flag.BoolVar(&resendSend, "resend", false, "Resend via the resend api (optional)")
	flag.IntVar(&refreshKeys, "refresh-keys", 0, "Refresh keys every X hours")
}

func loadEncryptionConfig() {
	enc = tls.Config{}
	if cer != "" && key != "" && !insecure {
		enc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if cer != "" && key != "" && cca {
		enc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if cer != "" && key != "" {
		cert, err := tls.LoadX509KeyPair(cer, key)
		if err != nil {
			log.Fatalf("Failed to load certificate: %v", err)
		}
		enc.Certificates = []tls.Certificate{cert}
	}
	if ca != "" {
		caData, err := os.ReadFile(ca)
		if err != nil {
			log.Fatalf("Failed to read CA file: %v", err)
		}
		enc.RootCAs = x509.NewCertPool()
		if !enc.RootCAs.AppendCertsFromPEM(caData) {
			log.Fatal("Failed to append CA certificate")
		}
	}
	if (enc.ClientAuth != tls.RequireAndVerifyClientCert && len(enc.Certificates) == 0) || aia {
		enc.InsecureSkipVerify = true
	}
	log.Printf("Encryption config reloaded at %s", time.Now().Format(time.RFC3339))
}

func main() {
	flag.Parse()

	loadEncryptionConfig()

	log.Printf("Running a %s SMTP server on port %d", func() string {
		if cer != "" && key != "" && !insecure {
			return "secure"
		}
		return "insecure"
	}(), port)

	serverPool = NewServerPool(2)
	if err := serverPool.Initialize(); err != nil {
		log.Fatalf("Failed to initialize server pool: %v", err)
	}

	proxyServer, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
	log.Printf("Proxy server listening on port %d", port)

	if refreshKeys > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(refreshKeys) * time.Hour)
			for range ticker.C {
				if err := refreshServer(); err != nil {
					log.Printf("Error refreshing server: %v", err)
				}
			}
		}()
	}

	for {
		conn, err := proxyServer.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleProxyConnection(conn)
	}
}

func handleProxyConnection(clientConn net.Conn) {
	defer clientConn.Close()

	serverInfo := serverPool.GetNextServer()
	if serverInfo == nil {
		log.Println("No SMTP servers available")
		clientConn.Write([]byte("421 Service not available, closing transmission channel\r\n"))
		return
	}

	serverConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", serverInfo.Port))
	if err != nil {
		log.Printf("Error connecting to SMTP server on port %d: %v", serverInfo.Port, err)
		clientConn.Write([]byte("421 Service not available, closing transmission channel\r\n"))
		return
	}
	defer serverConn.Close()

	log.Printf("Connected to SMTP server on port %d", serverInfo.Port)

	go io.Copy(serverConn, clientConn)
	io.Copy(clientConn, serverConn)
}

type Backend struct{}

func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}


type Session struct {
	From     string
	To       []string
	DataBuf  []byte
	Password string
}

func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *Session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		s.Password = password
		return nil
	}), nil
}


func (s *Session) AuthPlain(username, password string) error {
	s.Password = password
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	addr, err := mail.ParseAddress(from)
	log.Println("Mail from: ", addr)
	if err != nil {
		return fmt.Errorf("invalid 'from' address: %v", err)
	}
	s.From = addr.Address
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	addr, err := mail.ParseAddress(to)
	log.Println("Mail to: ", addr)
	if err != nil {
		return fmt.Errorf("invalid 'to' address: %v", err)
	}
	s.To = append(s.To, addr.Address)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	var err error
log.Println("HTere")	
	s.DataBuf, err = io.ReadAll(r)
	if err != nil {
		return err
	}
log.Println("Here")
	msg, err := mail.ReadMessage(bytes.NewReader(s.DataBuf))
	if err != nil {
		return err
	}
log.Println("Unparsed email: ", msg)
	parsedEmail, err := parseEmail(msg)
	
	
	if err != nil {
		return err
	}

	if resendSend {
		if err := sendEmail(parsedEmail, s.Password); err != nil {
			log.Printf("Error sending email: %v", err)
		}
	} else {
		if err := saveEmailLocally(parsedEmail, s.Password); err != nil {
			log.Printf("Error saving email locally: %v", err)
		}
	}

	return nil
}

func (s *Session) Reset() {
	s.From = ""
	s.To = nil
	s.DataBuf = nil
}

func (s *Session) Logout() error {
	return nil
}



func saveAttachment(filename string, content []byte) string {
	tempDir := os.TempDir()
	randPrefix := fmt.Sprintf("%d", rand.Int())
	filePath := filepath.Join(tempDir, randPrefix+filename)
	
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		log.Printf("Error saving attachment: %v", err)
		return ""
	}
	
	return filePath
}

type EmailData struct {
	From        string
	Name        string
	To          string
	Subject     string
	Text        string
	HTML        string
	Headers     map[string]string
	Attachments []Attachment
}

type Attachment struct {
	Filename    string
	Content     []byte
	ContentType string
}

func parseEmail(msg *mail.Message) (*EmailData, error) {
	emailData := &EmailData{
		Headers: make(map[string]string),
	}

	fmt.Println("Headers: ", msg)

	// Parse headers
	for k, v := range msg.Header {
		emailData.Headers[k] = strings.Join(v, ", ")
	}

	// Parse From
	if from, err := msg.Header.AddressList("From"); err == nil && len(from) > 0 {
		emailData.From = from[0].Address
		emailData.Name = from[0].Name
	}

	// Parse To
	if to, err := msg.Header.AddressList("To"); err == nil {
		var toAddresses []string
		for _, addr := range to {
			toAddresses = append(toAddresses, addr.Address)
		}
		emailData.To = strings.Join(toAddresses, ", ")
	}

	// Parse Subject
	emailData.Subject = msg.Header.Get("Subject")

	// Parse Body
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// If Content-Type is not set, assume it's plain text
		contentType = "text/plain; charset=utf-8"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			slurp, err := io.ReadAll(p)
			if err != nil {
				return nil, err
			}

			disposition, _, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
			if disposition == "attachment" {
				filename := p.FileName()
				contentType := p.Header.Get("Content-Type")
				emailData.Attachments = append(emailData.Attachments, Attachment{
					Filename:    filename,
					Content:     slurp,
					ContentType: contentType,
				})
			} else {
				partContentType := p.Header.Get("Content-Type")
				if strings.HasPrefix(partContentType, "text/plain") {
					emailData.Text = string(slurp)
				} else if strings.HasPrefix(partContentType, "text/html") {
					emailData.HTML = string(slurp)
				}
			}
		}
	} else {
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(mediaType, "text/plain") {
			emailData.Text = string(body)
		} else if strings.HasPrefix(mediaType, "text/html") {
			emailData.HTML = string(body)
		} else {
			// If it's neither plain text nor HTML, default to plain text
			emailData.Text = string(body)
		}
	}

	return emailData, nil
}

func sendEmail(emailData *EmailData, apiKey string) error {
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		return fmt.Errorf("API_URL environment variable is not set")
	}

	payload := map[string]interface{}{
		"from":    emailData.From,
		"name":    emailData.Name,
		"to":      emailData.To,
		"subject": emailData.Subject,
		"headers": emailData.Headers,
	}

	if emailData.HTML != "" {
		payload["html"] = emailData.HTML
	} else if emailData.Text != "" {
		payload["text"] = emailData.Text
	}

	if len(emailData.Attachments) > 0 {
		attachments := make([]map[string]string, len(emailData.Attachments))
		for i, att := range emailData.Attachments {
			attachments[i] = map[string]string{
				"filename":    att.Filename,
				"content":     base64.StdEncoding.EncodeToString(att.Content),
				"contentType": att.ContentType,
			}
		}
		payload["attachments"] = attachments
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling email data: %v", err)
	}

	req, err := http.NewRequest("POST", apiURL+"/send", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Println("Email sent successfully")
	return nil
}

func saveEmailLocally(emailData *EmailData, password string) error {
	fullObj := FullObj{
		User:     "", // We don't have user information in this context
		Password: password,
		Email:    *emailData,
	}

	jsonData, err := json.MarshalIndent(fullObj, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling email data: %v", err)
	}

	if pipeProgram != "" {
		tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("%d.json", rand.Int()))
		if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
			return fmt.Errorf("error writing temporary file: %v", err)
		}

		cmd := exec.Command(pipeProgram, tempFile)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error executing pipe program: %v", err)
		}

		log.Printf("Pipe program output: %s", string(output))

		if err := os.Remove(tempFile); err != nil {
			log.Printf("Error removing temporary file: %v", err)
		}
	} else {
		log.Println(string(jsonData))
	}

	return nil
}

type ServerPool struct {
	Size    int
	Servers []*SMTPServer
	Index   int
}

type SMTPServer struct {
	Server *smtp.Server
	Port   int
}

func NewServerPool(size int) *ServerPool {
	return &ServerPool{
		Size:    size,
		Servers: make([]*SMTPServer, 0, size),
	}
}

func (sp *ServerPool) Initialize() error {
	for i := 0; i < sp.Size; i++ {
		if err := sp.AddServer(); err != nil {
			return err
		}
	}
	return nil
}

func (sp *ServerPool) AddServer() error {
	if len(sp.Servers) >= sp.Size {
		log.Println("Server pool is already at maximum capacity. Not adding a new server.")
		return nil
	}

	s := smtp.NewServer(&Backend{})
	s.Addr = ":0"
	s.Domain = name
	s.ReadTimeout = 10 * time.Second
	s.WriteTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true



	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		if err := s.Serve(listener); err != nil {
			log.Printf("Error serving SMTP server: %v", err)
		}
	}()

	sp.Servers = append(sp.Servers, &SMTPServer{Server: s, Port: port})
	log.Printf("Added new SMTP server on port %d", port)

	return nil
}

func (sp *ServerPool) GetNextServer() *SMTPServer {
	if len(sp.Servers) == 0 {
		return nil
	}
	server := sp.Servers[sp.Index]
	sp.Index = (sp.Index + 1) % len(sp.Servers)
	return server
}

func (sp *ServerPool) RefreshServer(index int) error {
	if index < 0 || index >= len(sp.Servers) {
		return fmt.Errorf("invalid server index for refresh")
	}

	oldServer := sp.Servers[index]

	newServer := smtp.NewServer(&Backend{})
	newServer.Addr = ":0"
	newServer.Domain = name
	newServer.ReadTimeout = 10 * time.Second
	newServer.WriteTimeout = 10 * time.Second
	newServer.MaxMessageBytes = 1024 * 1024
	newServer.MaxRecipients = 50
	newServer.AllowInsecureAuth = true

	listener, err := net.Listen("tcp", newServer.Addr)
	if err != nil {
		return err
	}

	newPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		if err := newServer.Serve(listener); err != nil {
			log.Printf("Error serving new SMTP server: %v", err)
		}
	}()

	log.Printf("Created new SMTP server on port %d", newPort)

	sp.Servers[index] = &SMTPServer{Server: newServer, Port: newPort}

	go func() {
		time.Sleep(30 * time.Second)
		if err := oldServer.Server.Close(); err != nil {
			log.Printf("Error closing old SMTP server: %v", err)
		}
		log.Printf("Closed old SMTP server on port %d", oldServer.Port)
	}()

	return nil
}

func (sp *ServerPool) RefreshAll() error {
	log.Println("Refreshing all servers...")
	for i := range sp.Servers {
		if err := sp.RefreshServer(i); err != nil {
			return err
		}
	}
	log.Println("All servers refreshed")
	return nil
}

func refreshServer() error {
	log.Println("Refreshing servers with new encryption config...")
	loadEncryptionConfig()

	return serverPool.RefreshAll()
}