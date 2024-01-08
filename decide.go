package main

import "fmt"

type PasswordDecisionResponse struct {
	Acceptable bool   `json:"acceptable"`
	Reason     string `json:"reason,omitempty"`
	Error      string `json:"error,omitempty"`
}

func DecideOk() PasswordDecisionResponse {
	return PasswordDecisionResponse{Acceptable: true}
}

func DecideBadRepeat() PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Reason:     "Contains repetitive or sequential characters (e.g. ‘aaaaaa’, ‘1234abcd’)",
	}
}

func DecideBadTooSort() PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Reason:     "password too short",
	}
}

func DecideBadTooLong() PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Reason:     "password is too long",
	}
}

func DecideBannedList() PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Reason:     "Password disallowed",
	}
}

func DecideBadOnCompromisedList(times int64) PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Reason:     fmt.Sprintf("appears in a list of compromised passwords %d times", times),
	}
}

func DecideError(message string) PasswordDecisionResponse {
	return PasswordDecisionResponse{
		Acceptable: false,
		Error:      message,
	}
}
