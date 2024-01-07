package main

import "strings"

func sequentialChars(password string) bool {
	// TODO: think of a more clever way to do this.  For now, just look out for some static strings
	for _, s := range []string{"1234", "6789", "abcd"} {
		if strings.Contains(password, s) {
			return true
		}
	}
	return false
}

func repeatsChar(s string) bool {
	var lastChar rune
	var lastCharCount = 0
	const maxAcceptRepeats = 3
	for _, c := range s {
		if c == lastChar {
			lastCharCount++
			if lastCharCount > maxAcceptRepeats {
				return true
			}
		} else {
			lastChar = c
			lastCharCount = 1
		}
	}

	return false
}
