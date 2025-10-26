package tfa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jordemort/traefik-forward-auth/internal/provider"
	"github.com/thomseddon/go-flags"
)

var config *Config

// Config holds the runtime application config
type Config struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	AuthHost               string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config                 func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains          []CookieDomain       `long:"cookie-domain" env:"COOKIE_DOMAIN" env-delim:"," description:"Domain(s) to set main auth cookie on, can be set multiple times"`
	InsecureCookie         bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies for main auth cookie"`
	CookieName             string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Main auth cookie Name"`
	CSRFCookieName         string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction          string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" choice:"auth" choice:"allow" description:"Default action"`
	DefaultProvider        string               `long:"default-provider" env:"DEFAULT_PROVIDER" default:"google" choice:"google" choice:"oidc" choice:"generic-oauth" description:"Default provider"`
	Domains                CommaSeparatedList   `long:"domain" env:"DOMAIN" env-delim:"," description:"Only allow given email domains, comma separated, can be set multiple times"`
	LifetimeString         int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Main auth cookie lifetime in seconds"`
	LogoutRedirect         string               `long:"logout-redirect" env:"LOGOUT_REDIRECT" description:"URL to redirect to following logout"`
	MatchWhitelistOrDomain bool                 `long:"match-whitelist-or-domain" env:"MATCH_WHITELIST_OR_DOMAIN" description:"Allow users that match *either* whitelist or domain (enabled by default in v3)"`
	Path                   string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString           string               `long:"secret" env:"SECRET" description:"Secret used for signing main auth cookie (required)" json:"-"`
	UserPath               string               `long:"user-id-path" env:"USER_ID_PATH" default:"email" description:"Dot notation path of a UserID for use with whitelist and X-Forwarded-User"`
	Whitelist              CommaSeparatedList   `long:"whitelist" env:"WHITELIST" env-delim:"," description:"Only allow given UserID, comma separated, can be set multiple times"`
	Port                   int                  `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`
	N8N       N8NConfig          `group:"n8n" namespace:"n8n" env-namespace:"N8N"`
	Rules     map[string]*Rule   `long:"rule.<name>.<param>" description:"Rule definitions, param can be: \"action\", \"rule\" or \"provider\""`

	// Filled during transformations
	Secret   []byte `json:"-"`
	Lifetime time.Duration

	// Legacy
	CookieDomainsLegacy CookieDomains `long:"cookie-domains" env:"COOKIE_DOMAINS" description:"DEPRECATED - Use \"cookie-domain\""`
	CookieSecretLegacy  string        `long:"cookie-secret" env:"COOKIE_SECRET" description:"DEPRECATED - Use \"secret\""  json:"-"`
	CookieSecureLegacy  string        `long:"cookie-secure" env:"COOKIE_SECURE" description:"DEPRECATED - Use \"insecure-cookie\""`
	ClientIdLegacy      string        `long:"client-id" env:"CLIENT_ID" description:"DEPRECATED - Use \"providers.google.client-id\""`
	ClientSecretLegacy  string        `long:"client-secret" env:"CLIENT_SECRET" description:"DEPRECATED - Use \"providers.google.client-id\""  json:"-"`
	PromptLegacy        string        `long:"prompt" env:"PROMPT" description:"DEPRECATED - Use \"providers.google.prompt\""`

	TrustedIPAddresses []string `long:"trusted-ip-address" env:"TRUSTED_IP_ADDRESS" env-delim:"," description:"List of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated"`
	trustedIPNetworks  []*net.IPNet
}

// NewGlobalConfig creates a new global config, parsed from command arguments
func NewGlobalConfig() *Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

// TODO: move config parsing into new func "NewParsedConfig"

// NewConfig parses and validates provided configuration into a config object
func NewConfig(args []string) (*Config, error) {
	c := &Config{
		Rules: map[string]*Rule{},
		N8N:   N8NConfig{CookieSecure: true},
	}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// TODO: as log flags have now been parsed maybe we should return here so
	// any further errors can be logged via logrus instead of printed?

	// TODO: Rename "Validate" method to "Setup" and move all below logic

	// Setup
	// Set default provider on any rules where it's not specified
	for _, rule := range c.Rules {
		if rule.Provider == "" {
			rule.Provider = c.DefaultProvider
		}
	}

	// Backwards compatability
	if c.CookieSecretLegacy != "" && c.SecretString == "" {
		fmt.Println("cookie-secret config option is deprecated, please use secret")
		c.SecretString = c.CookieSecretLegacy
	}
	if c.ClientIdLegacy != "" {
		c.Providers.Google.ClientID = c.ClientIdLegacy
	}
	if c.ClientSecretLegacy != "" {
		c.Providers.Google.ClientSecret = c.ClientSecretLegacy
	}
	if c.PromptLegacy != "" {
		fmt.Println("prompt config option is deprecated, please use providers.google.prompt")
		c.Providers.Google.Prompt = c.PromptLegacy
	}
	if c.CookieSecureLegacy != "" {
		fmt.Println("cookie-secure config option is deprecated, please use insecure-cookie")
		secure, err := strconv.ParseBool(c.CookieSecureLegacy)
		if err != nil {
			return c, err
		}
		c.InsecureCookie = !secure
	}
	if len(c.CookieDomainsLegacy) > 0 {
		fmt.Println("cookie-domains config option is deprecated, please use cookie-domain")
		c.CookieDomains = append(c.CookieDomains, c.CookieDomainsLegacy...)
	}

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}
	c.Secret = []byte(c.SecretString)
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	// N8N JWT Lifetime
	c.N8N.jwtLifetime = time.Hour * time.Duration(c.N8N.JwtLifetimeHours)

	// Infer N8N Cookie Secure based on main InsecureCookie if not explicitly set via N8N_COOKIE_SECURE
	if os.Getenv("N8N_COOKIE_SECURE") == "" { // Check if env var was explicitly set
		c.N8N.CookieSecure = !c.InsecureCookie
	}

	if err := c.parseTrustedNetworks(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) parseTrustedNetworks() error {
	c.trustedIPNetworks = make([]*net.IPNet, len(c.TrustedIPAddresses))

	for i := range c.TrustedIPAddresses {
		addr := c.TrustedIPAddresses[i]
		if strings.Contains(addr, "/") {
			_, net, err := net.ParseCIDR(addr)
			if err != nil {
				return err
			}
			c.trustedIPNetworks[i] = net
			continue
		}

		ipAddr := net.ParseIP(addr)
		if ipAddr == nil {
			return fmt.Errorf("invalid ip address: '%s'", ipAddr)
		}

		c.trustedIPNetworks[i] = &net.IPNet{
			IP:   ipAddr,
			Mask: []byte{255, 255, 255, 255},
		}
	}

	return nil
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default|flags.IniUnknownOptionHandler)
	p.UnknownOptionHandler = c.parseUnknownFlag

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		// Try parsing at as an ini
		err := i.ParseFile(s)

		// If it fails with a syntax error, try converting legacy to ini
		if err != nil && strings.Contains(err.Error(), "malformed key=value") {
			converted, convertErr := convertLegacyToIni(s)
			if convertErr != nil {
				// If conversion fails, return the original error
				return err
			}

			fmt.Println("config format deprecated, please use ini format")
			return i.Parse(converted)
		}

		return err
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handleFlagError(err)
	}

	return nil
}

func (c *Config) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	// Parse rules in the format "rule.<name>.<param>"
	parts := strings.Split(option, ".")
	if len(parts) == 3 && parts[0] == "rule" {
		// Ensure there is a name
		name := parts[1]
		if len(name) == 0 {
			return args, errors.New("route name is required")
		}

		// Get value, or pop the next arg
		val, ok := arg.Value()
		if !ok && len(args) > 1 {
			val = args[0]
			args = args[1:]
		}

		// Check value
		if len(val) == 0 {
			return args, errors.New("route param value is required")
		}

		// Unquote if required
		if val[0] == '"' {
			var err error
			val, err = strconv.Unquote(val)
			if err != nil {
				return args, err
			}
		}

		// Get or create rule
		rule, ok := c.Rules[name]
		if !ok {
			rule = NewRule()
			c.Rules[name] = rule
		}

		// Add param value to rule
		switch parts[2] {
		case "action":
			rule.Action = val
		case "rule":
			rule.Rule = val
		case "provider":
			rule.Provider = val
		case "whitelist":
			list := CommaSeparatedList{}
			list.UnmarshalFlag(val)
			rule.Whitelist = list
		case "domains":
			list := CommaSeparatedList{}
			list.UnmarshalFlag(val)
			rule.Domains = list
		default:
			return args, fmt.Errorf("invalid route param: %v", option)
		}
	} else {
		return args, fmt.Errorf("unknown flag: %v", option)
	}

	return args, nil
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}

	return err
}

var legacyFileFormat = regexp.MustCompile(`(?m)^([a-z-]+) (.*)$`)

func convertLegacyToIni(name string) (io.Reader, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(legacyFileFormat.ReplaceAll(b, []byte("$1=$2"))), nil
}

// Validate validates a config object
func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set")
	}

	if c.N8N.Enabled {
		if c.N8N.DbConnectionString == "" {
			log.Fatal("\"n8n.db-connection-string\" option must be set when \"n8n.enabled\" is true")
		}
		if c.N8N.JwtSecret == "" {
			log.Fatal("\"n8n.jwt-secret\" option must be set when \"n8n.enabled\" is true")
		}
		// Valida SameSite
		validSameSite := map[string]http.SameSite{
			"lax":    http.SameSiteLaxMode,
			"strict": http.SameSiteStrictMode,
			"none":   http.SameSiteNoneMode,
		}
		if _, ok := validSameSite[strings.ToLower(c.N8N.CookieSameSite)]; !ok {
			log.Fatalf("invalid value for \"n8n.cookie-same-site\": %s. Must be one of lax, strict, none", c.N8N.CookieSameSite)
		}
	}

	// Setup default provider
	err := c.setupProvider(c.DefaultProvider)
	if err != nil {
		log.Fatal(err)
	}

	// Check rules (validates the rule and the rule provider)
	for _, rule := range c.Rules {
		err = rule.Validate(c)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

// GetProvider returns the provider of the given name
func (c *Config) GetProvider(name string) (provider.Provider, error) {
	switch name {
	case "google":
		return &c.Providers.Google, nil
	case "oidc":
		return &c.Providers.OIDC, nil
	case "generic-oauth":
		return &c.Providers.GenericOAuth, nil
	}

	return nil, fmt.Errorf("Unknown provider: %s", name)
}

// GetConfiguredProvider returns the provider of the given name, if it has been
// configured. Returns an error if the provider is unknown, or hasn't been configured
func (c *Config) GetConfiguredProvider(name string) (provider.Provider, error) {
	// Check the provider has been configured
	if !c.providerConfigured(name) {
		return nil, fmt.Errorf("Unconfigured provider: %s", name)
	}

	return c.GetProvider(name)
}

func (c *Config) IsIPAddressAuthenticated(address string) (bool, error) {
	addr := net.ParseIP(address)
	if addr == nil {
		return false, fmt.Errorf("invalid ip address: '%s'", address)
	}

	for _, n := range c.trustedIPNetworks {
		if n.Contains(addr) {
			return true, nil
		}
	}

	return false, nil
}

func (c *Config) providerConfigured(name string) bool {
	// Check default provider
	if name == c.DefaultProvider {
		return true
	}

	// Check rule providers
	for _, rule := range c.Rules {
		if name == rule.Provider {
			return true
		}
	}

	return false
}

func (c *Config) setupProvider(name string) error {
	// Check provider exists
	p, err := c.GetProvider(name)
	if err != nil {
		return err
	}

	// Setup
	if err := p.Setup(); err != nil {
		return err
	}

	return nil
}

// Rule holds defined rules
type Rule struct {
	Action    string
	Rule      string
	Provider  string
	Whitelist CommaSeparatedList
	Domains   CommaSeparatedList
}

// NewRule creates a new rule object
func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

func (r *Rule) formattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

// Validate validates a rule
func (r *Rule) Validate(c *Config) error {
	if r.Action != "auth" && r.Action != "allow" {
		return errors.New("invalid rule action, must be \"auth\" or \"allow\"")
	}

	return c.setupProvider(r.Provider)
}

// Legacy support for comma separated lists

// CommaSeparatedList provides legacy support for config values provided as csv
type CommaSeparatedList []string

// UnmarshalFlag converts a comma separated list to an array
func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

// MarshalFlag converts an array back to a comma separated list
func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}

// N8NConfig holds configuration for N8N user provisioning
type N8NConfig struct {
	Enabled            bool   `long:"enabled" env:"ENABLED" description:"Enable N8N integration (auto-provisioning and JWT cookie)"`
	DbConnectionString string `long:"db-connection-string" env:"DB_CONNECTION_STRING" description:"PostgreSQL connection string for N8N database" json:"-"`
	JwtSecret          string `long:"jwt-secret" env:"JWT_SECRET" description:"N8N JWT secret key (must match N8N_JWT_SECRET)" json:"-"`
	JwtLifetimeHours   int    `long:"jwt-lifetime-hours" env:"JWT_LIFETIME_HOURS" default:"168" description:"N8N JWT lifetime in hours (default: 168 hours / 7 days)"`
	CookieName         string `long:"cookie-name" env:"COOKIE_NAME" default:"n8n-auth" description:"N8N authentication cookie name"`
	CookieDomain       string `long:"cookie-domain" env:"COOKIE_DOMAIN" description:"Domain to set N8N auth cookie on (optional, defaults to request host or cookie-domain)"`
	CookieSecure       bool   `long:"cookie-secure" env:"COOKIE_SECURE" description:"Use secure attribute for N8N cookie (set automatically based on proto if not specified)"`
	CookieSameSite     string `long:"cookie-same-site" env:"COOKIE_SAME_SITE" default:"lax" choice:"lax" choice:"strict" choice:"none" description:"SameSite attribute for N8N cookie"`

	jwtLifetime time.Duration
}
