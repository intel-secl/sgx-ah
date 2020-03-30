/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"errors"
	"regexp"
)

var (
	nameReg    = regexp.MustCompile(`^[A-Za-z0-9-_.]+$`)
)

// ValidateNameString is used to check if the string is a valid name string
func ValidateNameString(nameString string) error {
	if !nameReg.MatchString(nameString) {
		return errors.New("invalid name string provided")
	}
	return nil
}