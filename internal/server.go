package tfa

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/jordemort/traefik-forward-auth/internal/provider"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	mux "github.com/traefik/traefik/v2/pkg/muxer/http"
	"golang.org/x/crypto/bcrypt"
)

// Server contains router and handler methods
type Server struct {
	muxer *mux.Muxer
	db    *sql.DB
}

type n8nUserData struct {
	ID         string
	Password   string
	MfaEnabled bool
	MfaSecret  sql.NullString
}

// NewServer creates a new server object and builds router
func NewServer(db *sql.DB) *Server {
	s := &Server{db: db}
	s.buildRoutes()
	return s
}

func escapeNewlines(data string) string {
	escapedData := strings.Replace(data, "\n", "", -1)
	escapedData = strings.Replace(escapedData, "\r", "", -1)
	return escapedData
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = mux.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}

	// Adds public routes if N8N is enabled.
	if config.N8N.Enabled {
		// Allow /healthz
		s.muxer.AddRoute("Path(`/healthz`)", 1, s.AllowHandler("n8n_healthz"))
		log.Debug("Added public route: /healthz")

		// Allow /mcp/
		s.muxer.AddRoute("PathPrefix(`/mcp/`)", 1, s.AllowHandler("n8n_mcp"))
		log.Debug("Added public route: /mcp/")

		// Allow /webhook/*
		webhookPath := fmt.Sprintf("PathPrefix(`/%s/`)", config.N8N.EndpointWebhook)
		s.muxer.AddRoute(webhookPath, 1, s.AllowHandler("n8n_webhook"))
		log.Debugf("Added public route: %s", webhookPath)

		// Allow /webhook-test/*
		webhookTestPath := fmt.Sprintf("PathPrefix(`/%s/`)", config.N8N.EndpointWebhookTest)
		s.muxer.AddRoute(webhookTestPath, 1, s.AllowHandler("n8n_webhook_test"))
		log.Debugf("Added public route: %s", webhookTestPath)
	}

	// Let's build a router
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			s.muxer.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			s.muxer.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.muxer.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.muxer.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.muxer.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		ipAddr := escapeNewlines(r.Header.Get("X-Forwarded-For"))
		if ipAddr == "" {
			logger.Warn("missing x-forwarded-for header")
		} else {
			ok, err := config.IsIPAddressAuthenticated(ipAddr)
			if err != nil {
				logger.WithField("error", err).Warn("Invalid forwarded for")
			} else if ok {
				logger.WithField("addr", ipAddr).Info("Authenticated remote address")
				w.WriteHeader(200)
				return
			}
		}

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		user, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateUser(user, rule)
		if !valid {
			logger.WithField("user", escapeNewlines(user)).Warn("Invalid user")
			http.Error(w, "User is not authorized", 401)
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", user)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := escapeNewlines(r.URL.Query().Get("state"))
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Validate redirect
		redirectURL, err := ValidateRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"receieved_redirect": redirect,
			}).Warnf("Invalid redirect in CSRF. %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user email from provider
		userEmail, err := p.GetUser(token, config.UserPath)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user from provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// --- INÍCIO: N8N Integração ---
		var n8nUser *n8nUserData
		if config.N8N.Enabled && s.db != nil {
			// 1. Provisiona (cria se não existe) o usuário no N8N DB
			err = s.provisionN8NUser(userEmail) // Usando userEmail obtido do provider
			if err != nil {
				logger.WithFields(logrus.Fields{
					"email": userEmail,
					"error": err,
				}).Error("Failed to provision N8N user")
				http.Error(w, "Service unavailable (user provisioning failed)", 503)
				return
			}

			// 2. Busca os dados necessários do usuário N8N para gerar o JWT
			n8nUser, err = s.getN8NUserData(userEmail)
			if err != nil {
				logger.WithFields(logrus.Fields{
					"email": userEmail,
					"error": err,
				}).Error("Failed to get N8N user data after provisioning")
				http.Error(w, "Service unavailable (failed to retrieve user data)", 503)
				return
			}
			if n8nUser == nil {
				// Isso não deveria acontecer se provisionN8NUser funcionou
				logger.WithField("email", userEmail).Error("N8N user not found after provisioning check")
				http.Error(w, "Internal Server Error (user inconsistency)", 500)
				return
			}

			// 3. Gera o JWT do N8N
			n8nJwtToken, err := s.generateN8NJwt(n8nUser, userEmail) // Passa o userEmail também
			if err != nil {
				logger.WithFields(logrus.Fields{
					"email": userEmail,
					"error": err,
				}).Error("Failed to generate N8N JWT")
				http.Error(w, "Service unavailable (JWT generation failed)", 503)
				return
			}

			// 4. Cria e define o cookie do N8N
			n8nCookie := s.makeN8NCookie(r, n8nJwtToken)
			http.SetCookie(w, n8nCookie)
			logger.WithFields(logrus.Fields{
				"email":   userEmail,
				"user_id": n8nUser.ID,
			}).Info("N8N JWT cookie set")

		}
		// --- FIM: N8N Integração ---

		// Gera o cookie principal do traefik-forward-auth (usa o email do provider)
		http.SetCookie(w, MakeCookie(r, userEmail))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     userEmail,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
}

// Search for user N8N data in the database
func (s *Server) getN8NUserData(email string) (*n8nUserData, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	user := &n8nUserData{}
	query := `SELECT id, password, "mfaEnabled", "mfaSecret" FROM public."user" WHERE email = $1`
	err := s.db.QueryRow(query, email).Scan(&user.ID, &user.Password, &user.MfaEnabled, &user.MfaSecret)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, fmt.Errorf("failed to query N8N user data: %w", err)
	}

	return user, nil
}

// Copy of N8N createJWTHash logic (using password hash)
func (s *Server) createN8NJwtHash(email string, n8nUser *n8nUserData) string {
	payloadParts := []string{email, n8nUser.Password} // Inclui o hash da senha!
	if n8nUser.MfaEnabled && n8nUser.MfaSecret.Valid && len(n8nUser.MfaSecret.String) >= 3 {
		payloadParts = append(payloadParts, n8nUser.MfaSecret.String[:3])
	}
	payload := strings.Join(payloadParts, ":")

	hasher := sha256.New()
	hasher.Write([]byte(payload))
	hashBytes := hasher.Sum(nil)

	// Codifica em Base64 e pega os primeiros 10 caracteres
	encodedHash := base64.StdEncoding.EncodeToString(hashBytes)
	if len(encodedHash) > 10 {
		return encodedHash[:10]
	}
	return encodedHash
}

// Generates N8N JWT token
func (s *Server) generateN8NJwt(n8nUser *n8nUserData, email string) (string, error) {
	n8nHash := s.createN8NJwtHash(email, n8nUser)
	now := time.Now()
	expiresAt := now.Add(config.N8N.jwtLifetime).Unix()
	issuedAt := now.Unix()

	// Payload N8N (omitindo browserId por simplicidade inicial)
	claims := jwt.MapClaims{
		"id":      n8nUser.ID,
		"hash":    n8nHash,
		"usedMfa": false, // Assumindo que MFA foi tratado pelo SSO externo
		"iat":     issuedAt,
		"exp":     expiresAt,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(config.N8N.JwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign N8N JWT: %w", err)
	}

	return signedToken, nil
}

// Creates the http.Cookie object for N8N
func (s *Server) makeN8NCookie(r *http.Request, token string) *http.Cookie {
	// Determina o domínio do cookie
	cookieDomain := config.N8N.CookieDomain
	if cookieDomain == "" {
		// Se não definido especificamente para N8N, tenta usar o domínio
		// principal do traefik-forward-auth ou o host da requisição
		cookieDomain = s.getEffectiveCookieDomain(r)
	}

	// Mapeia SameSite string para http.SameSite
	sameSiteMode := http.SameSiteLaxMode // Default
	switch strings.ToLower(config.N8N.CookieSameSite) {
	case "strict":
		sameSiteMode = http.SameSiteStrictMode
	case "none":
		sameSiteMode = http.SameSiteNoneMode
	}

	return &http.Cookie{
		Name:     config.N8N.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   cookieDomain,
		MaxAge:   int(config.N8N.jwtLifetime.Seconds()), // Usa MaxAge para cookies de sessão
		HttpOnly: true,
		Secure:   config.N8N.CookieSecure,
		SameSite: sameSiteMode,
	}
}

// Helper function to determine the domain of the N8N cookie
func (s *Server) getEffectiveCookieDomain(r *http.Request) string {
	// Checks if any of the configured primary domains matches the current host
	// Removes the host port from the request before comparing
	reqHost := r.Host
	if idx := strings.LastIndex(reqHost, ":"); idx != -1 {
		reqHost = reqHost[:idx]
	}

	for _, d := range config.CookieDomains {
		if d.Match(reqHost) {
			return d.Domain // Retorna o domínio configurado se houver correspondência
		}
	}
	// If no configured domain matches, return just the host (no port)
	return reqHost
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// clean existing CSRF cookie
	for _, v := range r.Cookies() {
		if strings.Contains(v.Name, config.CSRFCookieName) {
			http.SetCookie(w, ClearCSRFCookie(r, v))
		}
	}
	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    escapeNewlines(r.Header.Get("X-Forwarded-Method")),
		"proto":     escapeNewlines(r.Header.Get("X-Forwarded-Proto")),
		"host":      escapeNewlines(r.Header.Get("X-Forwarded-Host")),
		"uri":       escapeNewlines(r.Header.Get("X-Forwarded-Uri")),
		"source_ip": escapeNewlines(r.Header.Get("X-Forwarded-For")),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}

func (s *Server) provisionN8NUser(email string) error {
	var exists bool
	// Check if the user exists
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM public."user" WHERE email = $1)`, email).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	if exists {
		log.WithField("email", email).Debug("N8N user already exists, skipping creation.")
		return nil
	}

	log.WithField("email", email).Info("New user. Provisioning N8N account...")

	// 2. User does not exist, create it in a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer tx.Rollback()

	newUserID := uuid.New().String()

	var firstName, lastName string
	emailParts := strings.Split(email, "@")
	nameParts := strings.Split(emailParts[0], ".")
	if len(nameParts) > 0 {
		firstName = strings.Title(nameParts[0])
	}
	if len(nameParts) > 1 {
		lastName = strings.Title(nameParts[len(nameParts)-1])
	}

	randomPassword, err := s.generateRandomString(20) // Ajuste o tamanho conforme necessário
	if err != nil {
		return fmt.Errorf("failed to generate random password: %w", err)
	}

	// Generate bcrypt hash of the random password
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	passwordHash := string(hashedPasswordBytes)
	log.WithField("email", email).Debugf("Generated temporary password hash for new user")

	projectID, err := s.generateRandomString(16)
	if err != nil {
		return fmt.Errorf("failed to generate project ID: %w", err)
	}

	projectName := fmt.Sprintf("%s <%s>", firstName, email)
	now := time.Now().UTC()

	// Query 1: Insert into public."user"
	_, err = tx.Exec(
		`INSERT INTO public."user" (id, email, "firstName", "lastName", password, "personalizationAnswers", "createdAt", "updatedAt", settings, disabled, "mfaEnabled", "mfaSecret", "mfaRecoveryCodes", "lastActiveAt", "roleSlug") 
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		newUserID, email, firstName, lastName, passwordHash, // 1-5
		nil, now, now, nil, false, // 6-10
		false, nil, nil, now, "global:member", // 11-15
	)
	if err != nil {
		return fmt.Errorf("failed to insert into user table: %w", err)
	}

	// Query 2: Insert into public.project
	_, err = tx.Exec(
		`INSERT INTO public.project (id, name, type, "createdAt", "updatedAt", icon, description) 
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		projectID, projectName, "personal", now, now, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to insert into project table: %w", err)
	}

	// Query 3: Insert into public.project_relation
	_, err = tx.Exec(
		`INSERT INTO public.project_relation ("projectId", "userId", role, "createdAt", "updatedAt") 
		 VALUES ($1, $2, $3, $4, $5)`,
		projectID, newUserID, "project:personalOwner", now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to insert into project_relation table: %w", err)
	}

	return tx.Commit()
}

func (s *Server) generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}
