package tfa

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jordemort/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
	mux "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains router and handler methods
type Server struct {
	muxer *mux.Muxer
	db    *sql.DB
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

		// Get user
		user, err := p.GetUser(token, config.UserPath)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		if s.db != nil {
			err := s.provisionN8NUser(user)
			if err != nil {
				logger.WithField("error", err).Error("Failed to provision N8N user")
				http.Error(w, "Service unavailable (user provisioning failed)", 503)
				return
			}
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
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

	passwordHash := "SSO"

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
