package cli

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"log"
	"syscall"
	"unicode/utf8"
)

type GetPasswordOptions struct {
	MinLength int
	Repeat    bool
}

func DefaultGetPasswordOptions() *GetPasswordOptions {

	opts := GetPasswordOptions{
		MinLength: 8,
		Repeat:    true,
	}

	return &opts
}

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
