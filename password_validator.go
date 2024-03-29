package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	gopwned "github.com/mavjs/goPwned"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

func ValidatePassword(c *gin.Context, password string, gopwnedClient *gopwned.Client, bannedPasswords BannedPasswordsList) {

	// TODO: "To make allowances for likely mistyping, verifiers MAY replace multiple consecutive space characters with a single space character prior to verification, provided that the result is at least 8 characters in length."

	// https://pkg.go.dev/unicode/utf8#RuneCountInString instead of a naive len byte count
	passwordLength := utf8.RuneCountInString(password)
	log.Trace().Str("password length", strconv.Itoa(passwordLength)).Msg("password length check")

	if passwordLength < MinPasswordLength {
		c.JSON(http.StatusOK, DecideBadTooSort())
		return
	}
	if passwordLength > MaxPasswordLength {
		c.JSON(http.StatusOK, DecideBadTooLong())
		return
	}

	// "Repetitive or sequential characters (e.g. ‘aaaaaa’, ‘1234abcd’)."
	if repeatsChar(password) || sequentialChars(password) {
		c.JSON(http.StatusOK, DecideBadRepeat())
		return
	}

	// "When processing requests to establish and change memorized secrets, verifiers SHALL compare the prospective
	// secrets against a list that contains values known to be commonly-used, expected, or compromised."

	// first, our own in-memory list of disallowed passwords
	if bannedPasswords.Contains(password) {
		c.JSON(http.StatusOK, DecideBannedList())
		return
	}

	// and then HIBP for "Passwords obtained from previous breach corpuses."
	pwdhash := hashPassword(password)
	log.Debug().Msg(pwdhash)
	fails, times := appearsInHIBP(gopwnedClient, pwdhash)
	if fails {
		if times == -1 {
			c.JSON(http.StatusInternalServerError, DecideError("Failed to consult compromise database, unable to issue result, please try again"))
			return
		}
		c.JSON(http.StatusOK, DecideBadOnCompromisedList(times))
		return
	}

	c.JSON(http.StatusOK, DecideOk())
	return
}

func ValidatePasswordHashedSha1(c *gin.Context, pwdhash string, gopwnedClient *gopwned.Client) {
	// for a hashed password, all we can really do is check it in HIBP

	// make sure it looks like 40 hex digits
	if len(pwdhash) != 40 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "does not look like a sha1"})
		return
	}

	// "Passwords obtained from previous breach corpuses."
	fails, times := appearsInHIBP(gopwnedClient, pwdhash)
	if fails {
		c.JSON(http.StatusOK, gin.H{
			"acceptable": false,
			"reason":     fmt.Sprintf("appears in a list of compromised passwords %d times", times)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"acceptable": true})
	return
}

func appearsInHIBP(client *gopwned.Client, pwdhash string) (bool, int64) {
	log.Trace().Str("pwdhash", pwdhash)

	// https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
	// we look up the range with the first 5 chars of the hash, then check the remaining part over the list returned in that range
	frange := pwdhash[0:5]
	lrange := pwdhash[5:40]

	// TODO: here would decide whether to look up a local file or call out to the API
	var respArray []string
	if viper.GetBool("hibp.local") {
		log.Error().Msg("HIBP local not yet implemented")
		// TODO: read from disk
		return true, -1
	} else {
		log.Trace().Str("frange", frange).Msg("calling HIBP")
		karray, err := client.GetPwnedPasswords(frange, false)
		if err != nil {
			panic("unable to get pwned passwords")
		}

		str_karray := string(karray)
		respArray = strings.Split(str_karray, "\r\n")
	}

	var result int64
	log.Debug().Int("found matches", len(respArray))
	for _, resp := range respArray {
		str_array := strings.Split(resp, ":")
		test := str_array[0]

		count, err := strconv.ParseInt(str_array[1], 0, 32)
		if err != nil {
			log.Panic().Str("val", str_array[1]).Msg("cannot read hibp file, may be corrupted")
			panic("unable to convert string into integer")
		}
		if test == lrange {
			log.Debug().Msg("password hash found in compromised list")
			result = count
			break
		}
	}
	if result > 1 {
		return true, result
	}

	return false, 0
}
