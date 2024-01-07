package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	gopwned "github.com/mavjs/goPwned"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"net/http"
	"os"
)

var db = make(map[string]string)

type Password struct {
	Password string `form:"password" json:"password"`
}
type PasswordHash struct {
	Hash string `form:"hash" json:"hash"`
}

const MaxPasswordLength = 128
const MinPasswordLength = 8

func hashPassword(plaintext string) string {
	h := sha1.New()
	h.Write([]byte(plaintext))
	sha1Hash := fmt.Sprintf("%X", h.Sum(nil))
	return sha1Hash
}

func setupRouter(gopwnedClient *gopwned.Client, passwords BannedPasswordsList) *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()

	// gin middleware, which I'm not sure we need
	r.Use(logger.SetLogger())

	// Ping test
	r.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	r.POST("/password/plaintext", func(c *gin.Context) {
		var password Password
		if err := c.ShouldBind(&password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			// validate password
			validatePassword(c, password.Password, gopwnedClient, passwords)
			return
		}
	})
	r.POST("/password/sha1", func(c *gin.Context) {
		var password PasswordHash
		if err := c.ShouldBind(&password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			// validate password
			validatePasswordHashedSha1(c, password.Hash, gopwnedClient)
			return
		}
	})

	return r
}

func main() {
	initConfig()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if viper.GetBool("Debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	bannedPasswords := NewBannedPasswordsList(viper.GetString("PasswordDisallowListPath"))

	gopwned := gopwned.NewClient(nil, "")

	r := setupRouter(gopwned, bannedPasswords)
	// Listen and Server in 0.0.0.0:8080
	log.Info().Msg("Starting server")
	if err := r.Run(":8080"); err != nil {
		log.Fatal().Err(err).Msg("cant start server")
	}
}

func initConfig() {
	viper.SetDefault("PasswordDisallowListPath", "data/disallow.txt")
	viper.SetDefault("Debug", false)
	if gin.IsDebugging() {
		viper.SetDefault("Debug", true)
	}

	viper.SetDefault("hibp.local", false)
	viper.SetEnvPrefix("PASSWORDS")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; sensible defaults
		} else {
			// Config file was found but another error was produced
		}
	}

}
