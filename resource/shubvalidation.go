/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"errors"
	"regexp"
	"strings"
)

var (
	nameReg = regexp.MustCompile(`^[A-Za-z0-9-_.]{1,31}$`)
	keyReg  = regexp.MustCompile(`^[A-Za-z0-9-_.]+$`)
	xssReg  = regexp.MustCompile(`(?i)^.*(<|>|Redirect|script|alert).*$`)
)

// validateNameString is used to check if the string is a valid name string
func validateNameString(nameString string) error {
	if !nameReg.MatchString(nameString) {
		return errors.New("invalid name string provided")
	}
	return nil
}

func validateKeyString(keyString string) error {
	if !keyReg.MatchString(keyString) {
		return errors.New("invalid key string provided")
	}
	return nil
}

func validateXSSString(xssString string) error {
	if xssReg.MatchString(xssString) {
		return errors.New("bad string provided")
	}
	return nil
}

func validateInput(tenant Tenant) string {
	log.Trace("resource/shubvalidation: validateInput() Entering")
	defer log.Trace("resource/shubvalidation: validateInput() Leaving")

	errors := make([]string, 0)

	if tenant.TenantName == "" {
		errors = append(errors, "tenant name cannot be empty")
	}

	validationErr := validateNameString(tenant.TenantName)
	if validationErr != nil {
		errors = append(errors, "Tenant name can only contain alphanumeric and special characters (. _ -). Only 31 characters are allowed")
	}

	var errorMessageEmptyNameAdded, errorMessageNameRegexAdded, emptyPropertiesAdded, errorMessageKeyAdded, errorMessageValueAdded, invalidPluginProperty bool

	if (tenant.Plugins == nil) || len(tenant.Plugins) == 0 {
		errors = append(errors, "Plugin information is mandatory")
	} else {
		for _, plugin := range tenant.Plugins {
			if !errorMessageEmptyNameAdded && plugin.PluginName == "" {
				errors = append(errors, "Plugin Name cannot be empty")
				errorMessageEmptyNameAdded = true
			}

			validationErr = validateNameString(plugin.PluginName)
			if !errorMessageNameRegexAdded && validationErr != nil {
				errors = append(errors, "Plugin name can only contain alphanumeric and special characters (. _ -). Only 31 characters are allowed")
				errorMessageNameRegexAdded = true
			}

			if (plugin.Properties == nil) || len(plugin.Properties) == 0 {
				errors = append(errors, "Plugin properties are mandatory")
				emptyPropertiesAdded = true
			}
			for _, property := range plugin.Properties {
				if !errorMessageKeyAdded && property.Key == "" {
					errors = append(errors, "Plugin property key cannot be empty")
					errorMessageKeyAdded = true
				}
				if !errorMessageValueAdded && property.Value == "" {
					errors = append(errors, "Plugin property value cannot be empty")
					errorMessageValueAdded = true
				}
				validationErr = validateKeyString(property.Key)
				if !errorMessageKeyAdded && validationErr != nil {
					errors = append(errors, "Plugin property key can only contain alphanumeric and special characters (. _ -)")
					errorMessageKeyAdded = true
				}
				validationErr = validateXSSString(property.Value)
				if !errorMessageValueAdded && validationErr != nil {
					errors = append(errors, "Invalid plugin property value")
					errorMessageValueAdded = true
				}
				if errorMessageEmptyNameAdded || errorMessageNameRegexAdded || emptyPropertiesAdded || errorMessageKeyAdded || errorMessageValueAdded {
					invalidPluginProperty = true
					break
				}
			}
			if invalidPluginProperty {
				break
			}
		}
	}
	return strings.Join(errors, ",")
}
