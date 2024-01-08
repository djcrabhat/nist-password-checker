package main

import (
	"bufio"
	"github.com/rs/zerolog/log"
	"os"
)

type BannedPasswordsList struct {
	Passwords map[string]bool
}

func NewBannedPasswordsList(path string) BannedPasswordsList {
	set := make(map[string]bool)
	// load set from list
	readFile, err := os.Open(path)

	if err != nil {
		log.Warn().Err(err).Msg("Cannot load ban list at " + path)
	} else {
		fileScanner := bufio.NewScanner(readFile)

		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			set[fileScanner.Text()] = true
		}

		readFile.Close()
		log.Debug().Int("banned_passwords", len(set)).Msg("Loaded banned passwords")
	}

	return BannedPasswordsList{
		Passwords: set,
	}
}

func (p BannedPasswordsList) Contains(password string) bool {
	_, ok := p.Passwords[password]
	return ok
}

func (p BannedPasswordsList) Add(password string) {
	p.Passwords[password] = true
}
