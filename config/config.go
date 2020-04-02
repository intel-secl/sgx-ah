/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"intel/isecl/lib/common/setup"
	"intel/isecl/sgx-attestation-hub/constants"
	"os"
	"path"
	"sync"
)

// should move this into lib common, as its duplicated across SAH and SAH

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile string
	Port       int
	Postgres   struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	AAS_API_URL string
	LogLevel    log.Level

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}

	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseUrl     string
	AuthServiceUrl string
	SchedulerTimer int
	Subject        struct {
		TLSCertCommonName string
		Organization      string
		Country           string
		Province          string
		Locality          string
	}
}

var mu sync.Mutex

var global *Configuration

func Global() *Configuration {
	log.Trace("config/config:Global() Entering")
	defer log.Trace("config/config:Global() Leaving")

	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (c *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

	var err error = nil

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		log.Error("CMS_BASE_URL is not defined in environment")
	}

	aasBaseUrl, err := c.GetenvString("AAS_BASE_URL", "AAS Base URL")
	if err == nil && aasBaseUrl != "" {
		conf.AuthServiceUrl = aasBaseUrl
	} else if conf.AuthServiceUrl == "" {
		log.Error("AAS_BASE_URL is not defined in environment")
	}

	tlsCertCN, err := c.GetenvString("SAH_TLS_CERT_CN", "SAH TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultSAHTlsCn
	}

	certOrg, err := c.GetenvString("SAH_CERT_ORG", "SAH Certificate Organization")
	if err == nil && certOrg != "" {
		conf.Subject.Organization = certOrg
	} else if conf.Subject.Organization == "" {
		conf.Subject.Organization = constants.DefaultSAHCertOrganization
	}

	certCountry, err := c.GetenvString("SAH_CERT_COUNTRY", "SAH Certificate Country")
	if err == nil && certCountry != "" {
		conf.Subject.Country = certCountry
	} else if conf.Subject.Country == "" {
		conf.Subject.Country = constants.DefaultSAHCertCountry
	}

	certProvince, err := c.GetenvString("SAH_CERT_PROVINCE", "SAH Certificate Province")
	if err == nil && certProvince != "" {
		conf.Subject.Province = certProvince
	} else if err != nil || conf.Subject.Province == "" {
		conf.Subject.Province = constants.DefaultSAHCertProvince
	}

	certLocality, err := c.GetenvString("SAH_CERT_LOCALITY", "SAH Certificate Locality")
	if err == nil && certLocality != "" {
		conf.Subject.Locality = certLocality
	} else if conf.Subject.Locality == "" {
		conf.Subject.Locality = constants.DefaultSAHCertLocality
	}

	schedulerTimeout, err := c.GetenvInt("SAH_SCHEDULER_TIMER", "SAHUB Scheduler Timeout Seconds")
	if err == nil && schedulerTimeout != 0 {
		conf.SchedulerTimer = schedulerTimeout
	} else if conf.SchedulerTimer == 0 {
		conf.SchedulerTimer = constants.DefaultSAHSchedulerTimer
	}

	return conf.Save()
}

func Load(path string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}
	c.configFile = path
	return &c
}
