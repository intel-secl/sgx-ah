/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	"time"
)

const (
	HomeDir                          = "/opt/sgx-attestation-hub/"
	ConfigDir                        = "/etc/sgx-attestation-hub/"
	ExecutableDir                    = "/opt/sgx-attestation-hub/bin/"
	ExecLinkPath                     = "/usr/bin/sgx-attestation-hub"
	RunDirPath                       = "/run/sgx-attestation-hub"
	LogDir                           = "/var/log/sgx-attestation-hub/"
	LogFile                          = LogDir + "sgx-attestation-hub.log"
	SecurityLogFile                  = LogDir + "sgx-attestation-hub-security.log"
	HTTPLogFile                      = LogDir + "http.log"
	ConfigFile                       = "config.yml"
	DefaultTLSCertFile               = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile                = ConfigDir + "tls.key"
	HubTimeStamp                     = "HubSchedulerRun.txt"
	TrustedJWTSigningCertsDir        = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir               = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd                 = "systemctl disable sgx-attestation-hub"
	HashingAlgorithm                 = crypto.SHA384
	CmsTlsCertDigestEnv              = "CMS_TLS_CERT_SHA384"
	SAHLogLevel                      = "SAH_LOGLEVEL"
	SAH_USER                         = "SAH_ADMIN_USERNAME"
	SAH_PASSWORD                     = "SAH_ADMIN_PASSWORD"
	DefaultReadTimeout               = 30 * time.Second
	DefaultReadHeaderTimeout         = 10 * time.Second
	DefaultWriteTimeout              = 10 * time.Second
	DefaultIdleTimeout               = 10 * time.Second
	DefaultMaxHeaderBytes            = 1 << 20
	DefaultLogEntryMaxLength         = 300
	DefaultAuthDefendMaxAttempts     = 5
	DefaultAuthDefendIntervalMins    = 5
	DefaultAuthDefendLockoutMins     = 15
	DefaultDBRotationMaxRowCnt       = 100000
	DefaultDBRotationMaxTableCnt     = 10
	DefaultSSLCertFilePath           = ConfigDir + "sgx-attestation-hub-dbcert.pem"
	ServiceName                      = "sgx-attestation-hub"
	SAHUserName                      = "sah"
	DefaultHttpPort                  = 9443
	DefaultKeyAlgorithm              = "rsa"
	DefaultKeyAlgorithmLength        = 3072
	DefaultSAHTlsSan                 = "127.0.0.1,localhost"
	DefaultSAHTlsCn                  = "SGX AH TLS Certificate"
	OpenStackPlugin                  = "Nova"
	KubernetesPlugin                 = "kubernetes"
	NovaPluginUserName               = "user.name"
	NovaPluginUserPassword           = "user.password"
	KubernetesClientKeystorePassword = "kubernetes.client.keystore.password"
	KubernetesServerKeystorePassword = "kubernetes.server.keystore.password"
	DefaultSAHSchedulerTimer         = 50
	DefaultSAHRefreshHours           = 24
	DefaultJwtValidateCacheKeyMins   = 60
	PublickeyLocation                = ConfigDir + "sgx_hub_public_key.pem"
	PrivatekeyLocation               = ConfigDir + "sgx_hub_private_key.pem"
	API_VERSION                      = "crd.isecl.intel.com/v1beta1"
	HOSTATTRIBUTES_CRD               = "HostAttributesCrd"
	URL_HOSTATTRIBUTES               = "hostattributes"
	PATH                             = "/apis/crd.isecl.intel.com/v1beta1/namespaces/default"
	SLASH                            = "/"
	/*Open Stack Specific Constants */
	RESOURCE_PATH_V3_AUTH_TOKEN                 = "/v3/auth/tokens"
	KEYSTONE_AUTH_TOKEN_HEADER_KEY              = "X-Subject-Token"
	RESOURCE_PATH_TRAITS                        = "/traits"
	PLACEMENT                                   = "placement"
	OPENSTACK_API_MICROVERSION_HEADER           = "OpenStack-API-Version"
	PLACEMENT_API_MICROVERSION_VALUE            = "placement 1.21"
	RESOURCE_PATH_RESOURCE_PROVIDERS_NAME_QUERY = "/resource_providers?name="
	RESOURCE_PATH_RESOURCE_PROVIDERS            = "/resource_providers/"
	MAX_RETRIES_DUE_TO_CONFLICTS                = 3
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
