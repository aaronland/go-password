// Package cli provides helpers for reading passwords from a terminal.
package cli

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"log"
	"syscall"
	"unicode/utf8"
)

// GetPasswordOptions configures GetPassword.
type GetPasswordOptions struct {
	// MinLength is the minimum password length in characters. It must be greater than zero.
	MinLength int
	// Repeat requires the password to be entered twice, with both entries matching.
	Repeat bool
}

// DefaultGetPasswordOptions returns options requiring a repeated password of at least 8 characters.
func DefaultGetPasswordOptions() *GetPasswordOptions {

	opts := GetPasswordOptions{
		MinLength: 8,
		Repeat:    true,
	}

	return &opts
}

// GetPassword prompts for a password on the terminal without echoing it, re-prompting until the
// entries match (if opts.Repeat is set) and meet opts.MinLength. The password is returned exactly
// as typed. An error is returned if the terminal can not be read.
func GetPassword(opts *GetPasswordOptions) (string, error) {

	if opts.MinLength <= 0 {
		return "", errors.New("You must specify a minimum password length")
	}

	password := ""

	for {

		fmt.Print("Enter Password: ")

		pswd1, err := term.ReadPassword(int(syscall.Stdin))

		if err != nil {
			return "", err
		}

		fmt.Println("")

		if opts.Repeat {

			fmt.Print("Enter Password (again): ")

			pswd2, err := term.ReadPassword(int(syscall.Stdin))

			if err != nil {
				return "", err
			}

			fmt.Println("")

			if string(pswd1) != string(pswd2) {
				log.Println("Passwords do not match")
				continue
			}
		}

		// The password is used exactly as typed (no whitespace trimming)
		// and its length is counted in characters, not bytes.
		password = string(pswd1)

		if utf8.RuneCountInString(password) < opts.MinLength {
			log.Println("Password is too short")
			password = ""
			continue
		}

		break
	}

	return password, nil
}
