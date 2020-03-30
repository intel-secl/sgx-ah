/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	HomeDir                       = "/opt/sgx-attestation-hub/"
	ConfigDir                     = "/etc/sgx-attestation-hub/"
	ExecutableDir                 = "/opt/sgx-attestation-hub/bin/"
	ExecLinkPath                  = "/usr/bin/sgx-attestation-hub"
	RunDirPath                    = "/run/sgx-attestation-hub"
	LogDir                        = "/var/log/sgx-attestation-hub/"
	LogFile                       = LogDir + "sgx-attestation-hub.log"
	SecurityLogFile               = LogDir + "sgx-attestation-hub-security.log"
	HTTPLogFile                   = LogDir + "http.log"
	ConfigFile                    = "config.yml"
	TLSCertFile                   = "cert.pem"
	TLSKeyFile                    = "key.pem"
	TrustedJWTSigningCertsDir     = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir            = ConfigDir + "certs/trustedca/"
	RootCADirPath                 = ConfigDir + "certs/cms-root-ca/"
	PIDFile                       = "sgx-attestation-hub.pid"
	ServiceRemoveCmd              = "systemctl disable sgx-attestation-hub"
	HashingAlgorithm              = crypto.SHA384
	PasswordRandomLength          = 20
	JWTCertsCacheTime             = "1m"
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
	DefaultDBRotationMaxRowCnt    = 100000
	DefaultDBRotationMaxTableCnt  = 10
	DefaultSSLCertFilePath        = ConfigDir + "sgx-attestation-hub-dbcert.pem"
	ServiceName                   = "sgx-attestation-hub"
	DefaultHttpPort               = 9443
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	DefaultSAHTlsSan              = "127.0.0.1,localhost"
	DefaultSAHTlsCn               = "SGX AH TLS Certificate"
	DefaultSAHCertOrganization    = "INTEL"
	DefaultSAHCertCountry         = "US"
	DefaultSAHCertProvince        = "SF"
	DefaultSAHCertLocality        = "SC"
	OpenStackPlugin               = "Nova"
	KubernetesPlugin              = "kubernetes"
	NovaPluginUserName            = "user.name"
	NovaPluginUserPassword        = "user.password"
	KubernetesClientKeystorePassword = "kubernetes.client.keystore.password"
	KubernetesServerKeystorePassword = "kubernetes.server.keystore.password"
	DefaultSAHRefreshHours	      = 24
	DefaultJwtValidateCacheKeyMins = 60
)

// State represents whether or not a daemon is running or not
type State bool
const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

