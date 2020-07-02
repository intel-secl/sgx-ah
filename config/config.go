/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	errorLog "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	commLog "intel/isecl/lib/common/v2/log"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/shub/constants"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

var slog = commLog.GetSecurityLogger()

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	CmsTlsCertDigest string
	Postgres         struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        log.Level

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}
	SHUB struct {
		User     string
		Password string
	}
	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseUrl string
	AuthServiceUrl string
	ShvsBaseUrl    string
	SchedulerTimer int
	Subject        struct {
		TLSCertCommonName string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
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

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	shubAASUser, err := c.GetenvString(constants.SHUB_USER, "SHUB Service Username")
	if err == nil && shubAASUser != "" {
		conf.SHUB.User = shubAASUser
	} else if conf.SHUB.User == "" {
		commLog.GetDefaultLogger().Error("SHUB_ADMIN_USERNAME is not defined in environment or configuration file")
		return errorLog.Wrap(err, "SHUB_ADMIN_USERNAME is not defined in environment or configuration file")
	}

	shubAASPassword, err := c.GetenvSecret(constants.SHUB_PASSWORD, "SHUB Service Password")
	if err == nil && shubAASPassword != "" {
		conf.SHUB.Password = shubAASPassword
	} else if strings.TrimSpace(conf.SHUB.Password) == "" {
		commLog.GetDefaultLogger().Error("SHUB_ADMIN_PASSWORD is not defined in environment or configuration file")
		return errorLog.Wrap(err, "SHUB_ADMIN_PASSWORD is not defined in environment or configuration file")
	}

	shvsBaseUrl, err := c.GetenvString("SHVS_BASE_URL", "SHVS Base URL")
	if err == nil && shvsBaseUrl != "" {
		conf.ShvsBaseUrl = shvsBaseUrl
	} else if conf.ShvsBaseUrl == "" {
		log.Error("SHVS_BASE_URL is not defined in environment")
	}

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasApiUrl, err := c.GetenvString("AAS_API_URL", "AAS API URL")
	if err == nil && aasApiUrl != "" {
		conf.AuthServiceUrl = aasApiUrl
	} else if conf.AuthServiceUrl == "" {
		commLog.GetDefaultLogger().Error("AAS_API_URL is not defined in environment")
		return errorLog.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	tlsCertCN, err := c.GetenvString("SHUB_TLS_CERT_CN", "SHUB TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultSHUBTlsCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file/directory where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	logLevel, err := c.GetenvString("SHUB_LOGLEVEL", "SHUB Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SHUBLogLevel)
		conf.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			conf.LogLevel = log.InfoLevel
		} else {
			conf.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultSHUBTlsSan
	}

	schedulerTimeout, err := c.GetenvInt("SHUB_SCHEDULER_TIMER", "SHUB Scheduler Timeout Seconds")
	if err == nil && schedulerTimeout != 0 {
		conf.SchedulerTimer = schedulerTimeout
	} else if conf.SchedulerTimer == 0 {
		conf.SchedulerTimer = constants.DefaultSHUBSchedulerTimer
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
