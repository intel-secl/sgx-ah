/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/json"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/resource/plugins"
	"intel/isecl/sgx-attestation-hub/types"
	"strconv"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	commLogMsg "intel/isecl/lib/common/v2/log/message"
	"io/ioutil"
)

type tenantConfig struct {
	TenantId   string         `json:"id"`
	TenantName string         `json:"name"`
	Plugins    []types.Plugin `json:"plugins"`
	Deleted    bool           `json:"deleted"`
}

type PlatformData struct {
	Sgx_enabled   bool   `json:"sgx-enabled"`
	Sgx_supported bool   `json:"sgx-supported"`
	Flc_enabled   bool   `json:"flc-enabled"`
	TcbUpToDate   bool   `json:"tcbUpToDate"`
	Epc_size      string `json:"epc-size"`
	ValidTo       string `json:"validTo"`
}

type Plugin1 types.Plugin
type hostDetails types.HostDetails

func (e *tenantConfig) GetConfigStruct(configuartion string) error {

	log.Trace("resource/sgx_plugin:GetConfigStruct() Entering: ")
	defer log.Trace("resource/sgx_plugin:GetConfigStruct() Leaving")

	err := json.Unmarshal(([]byte(configuartion)), e)
	if err != nil {
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	return nil
}

func GetCredentials(configuartion string, prop *[]types.Property) error {
	log.Trace("resource/sgx_plugin:GetCredentials() Entering")
	defer log.Trace("resource/sgx_plugin:GetCredentials() Leaving")
	err := json.Unmarshal(([]byte(configuartion)), prop)
	if err != nil {
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	return err
}

func GetAHPublicKey() []byte {
	rsaPublicKeyLocation := constants.PublickeyLocation
	pubKey, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.WithError(err).Info("Error in reading the hub pem file")
	}
	return pubKey
}

func createSignedTrustReport(createSignedTrustReport string) (string, error) {
	log.Trace("In createSignedTrustReport")
	///Get the privateKeyFromPath
	var privateKey *rsa.PrivateKey
	rsaPrivateKeyLocation := constants.PrivatekeyLocation
	rsaPublicKeyLocation := constants.PublickeyLocation

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.WithError(err).Info("no rsa private key found")
		return "", errors.Wrap(err, "no rsa key file path provided")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(priv)
	if err != nil {
		log.WithError(err).Info("Cannot parse RSA private key from file")
		return "", errors.Wrap(err, "Cannot parse RSA private key from file")
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Error("Unable to parse RSA private key")
		return "", errors.New("Unable to parse RSA private key")
	}

	publicKey, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.WithError(err).Info("no rsa key file path provided")
		return "", errors.Wrap(err, "no rsa key file path provided")
	}
	pubPem, _ := pem.Decode(publicKey)
	if pubPem == nil {
		slog.Error(commLogMsg.InvalidInputBadEncoding)
		return "", errors.New("rsa public key not decoded")
	}

	h := sha1.New()
	h.Write(pubPem.Bytes)
	bs := h.Sum(nil)
	keyIdStr := base64.StdEncoding.EncodeToString(bs)

	header := make(map[string]string)
	header["alg"] = "RS384"
	header["typ"] = "JWT"
	header["kid"] = keyIdStr
	b, _ := json.Marshal(header)

	hashEntity := sha512.New384()
	hashEntity.Write([]byte(createSignedTrustReport))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashEntity.Sum(nil))
	signedTrustReportBytes := base64.StdEncoding.EncodeToString([]byte(createSignedTrustReport))
	str1 := base64.StdEncoding.EncodeToString(b)
	signatureString := str1 + "." + signedTrustReportBytes + "." + base64.StdEncoding.EncodeToString(signature)
	return signatureString, nil
}

func SynchAttestationInfo(db repository.SAHDatabase) error {
	log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Entering")
	defer log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Leaving")

	ext_tennats, err := db.TenantRepository().RetrieveAllActiveTenants()
	if ext_tennats == nil {
		log.Debug("No tenants configured")
		return err
	}
	for _, tenant := range ext_tennats {
		///Read Tenant Configuration
		///Get configuration string and convert that string to corresponding key value pair
		/// get ahMapping data: getHostHardwareUuid()
		///get hosts data for the getHostHardwareUuid()
		///	populateHostDetails()
		configuartion := tenant.Config
		configStruct := new(tenantConfig)
		///configuartion is a string containing keys and values information
		err = configStruct.GetConfigStruct(configuartion)
		if err != nil {
			log.Error("synchAttestationInfo: Failed to get configurations for tenant: ", tenant.Id)
			log.WithError(err).WithField("tenant id", tenant.Id).Info("synchAttestationInfo: Failed to get configurations for tenant")
			continue
		}
		tenant_mapping, err := db.HostTenantMappingRepository().RetrieveAll(types.HostTenantMapping{TenantUUID: tenant.Id, Deleted: false})
		if err != nil {
			log.WithError(err).WithField("tenant id", tenant.Id).Info("synchAttestationInfo: Failed to get tenant mapping")
			continue
		} else if len(tenant_mapping) == 0 {
			log.Error("synchAttestationInfo: no host assigned to the tenant: ", tenant.Id)
			continue
		}
		log.Debug("tenant_mapping retrieved: ", len(tenant_mapping))

		var hostDataSlice []types.HostDetails
		for _, mapping := range tenant_mapping {
			hardwareuuid := mapping.HostHardwareUUID
			host, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: hardwareuuid, Deleted: false})
			if host == nil {
				log.Error("synchAttestationInfo: No host with this uuid: ", hardwareuuid)
				continue
			}
			hostDetailsPtr, err := populateHostDetails(host)
			if err != nil {
				log.WithError(err).Info("synchAttestationInfo: Failed to get configurations")
				continue
			}

			///Now add the host in a list of hosts
			hostDataSlice = append(hostDataSlice, *hostDetailsPtr)
		}
		log.Trace("Number of hosts to the tenant: ", len(hostDataSlice))
		err = processDataToPlugins(tenant, hostDataSlice, configStruct.Plugins, db)
		if err != nil {
			log.Error("synchAttestationInfo: Failed to push data: ", err)
			log.WithError(err).Info("synchAttestationInfo: Failed to push data")
		}
	}
	return nil
}

func processDataToPlugins(t1 types.Tenant, h1 []types.HostDetails, p1 []types.Plugin, db repository.SAHDatabase) error {
	log.Trace("resource/processDataToPlugins: processDataToPlugins() Entering")
	defer log.Trace("resource/processDataToPlugins: processDataToPlugins() Leaving")
	for _, plugin := range p1 {
		var pData types.PublishData
		pData.TenantId = t1.Id
		pData.Host_details = h1
		var value string
		for _, property := range plugin.Properties {
			if property.Key == "plugin.provider" {
				value = property.Value
				break
			}
		}
		if value == "" {
			////report error
			log.Error("value of plugin provider is null")
			return errors.New("value of plugin provider is null")
		}
		///Get Plugin class name
		err := addCredentialToPlugin(t1, &plugin, db)
		if err != nil {
			log.WithError(err).Info("got error while adding Credentials")
			return errors.Wrap(err, "Couldn't add credentials for plugin")
		}
		if value == "Kubernetes" {
			var k1 plugins.Kubernetes
			err := k1.Pushdata(pData, plugin)
			if err != nil {
				log.WithError(err).Info("got error while pushing the data to Kubernetes")
				return err
			}
		} else if value == "OpenStack" {
			var o1 plugins.OpenStack
			err := o1.Pushdata(pData, plugin)
			if err != nil {
				log.WithError(err).Info("got error while pushing the data to openstack")
				return err
			}

		} else {
			///error
			log.Error("plugin provider doesn't match")
			return errors.New("plugin provider doesn't match")
		}
	}
	return nil
}

func addCredentialToPlugin(t1 types.Tenant, p1 *types.Plugin, db repository.SAHDatabase) error {
	credential := types.TenantPluginCredential{
		TenantUUID: t1.Id,
		PluginName: p1.Name,
	}
	plugin_credential, err := db.TenantPluginCredentialRepository().Retrieve(credential)
	if err != nil {
		log.WithError(err).WithField("tenant id", t1.Id).Info("didn't find any credential for plugin of tenant")
		return errors.Wrap(err, "didn't find any credential for plugin")
	}
	///Get all the credenials from db which will come as a string.
	///This string is converted into json key value pair of type
	var credential_properties []types.Property
	///configuartion is a string containing keys and values information
	err = GetCredentials(plugin_credential.Credential, &credential_properties)
	if err != nil {
		log.WithError(err).Info("couldn't get any credentials")
		return errors.Wrap(err, "couldn't get any credentials")
	}
	log.Debug("credential_properties: ", credential_properties)
	///Now add the property array to Plugin array
	for _, prop := range credential_properties {
		p1.Properties = append(p1.Properties, prop)
	}
	log.Debug("values of plugins after credentials: ", p1)
	return nil
}

func populateHostDetails(h1 *types.Host) (*types.HostDetails, error) {
	details := new(types.HostDetails)
	details.Uuid = h1.Id
	details.HardwareUuid = h1.HardwareUUID
	details.Hostname = h1.HostName

	hostPlatformData := new(PlatformData)
	hostPlatformData.Sgx_enabled = h1.SGXEnabled
	hostPlatformData.Sgx_supported = h1.SGXSupported
	hostPlatformData.Flc_enabled = h1.FLCEnabled
	hostPlatformData.TcbUpToDate = h1.TCBUpToDate
	hostPlatformData.Epc_size = h1.EPCSize
	hostPlatformData.Epc_size = strings.Replace(hostPlatformData.Epc_size, " ", "", -1) ///This is so because in K8S CRD can't have spaces

	twiceSchedulerTime := strconv.Itoa(constants.DefaultSAHSchedulerTimer * 2)
	parsedDuration, _ := time.ParseDuration(twiceSchedulerTime + "s")
	updatedTime := time.Now().UTC().Add(parsedDuration)
	formattedTime := updatedTime.Format(time.RFC3339)
	parsedTime, err := time.Parse(time.RFC3339, h1.ValidTo)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing time string")
	}

	if parsedTime.After(updatedTime) {
		hostPlatformData.ValidTo = h1.ValidTo
	} else{
		hostPlatformData.ValidTo = formattedTime
	}

	log.Debug("hostPlatformData: ", hostPlatformData)
	trustReportBytes, err := (json.Marshal(hostPlatformData))
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal hostPlatformData to get trustReport")
	}
	trustReport := string(trustReportBytes)
	signedTrustReport, err := createSignedTrustReport(trustReport)
	if err != nil {
		return nil, errors.Wrap(err, "synchAttestationInfo: Failed to get signed trust report")
	}
	details.Trust_report = trustReport
	details.Signed_trust_report = signedTrustReport ///same as details.trust_report only difference this that this signed
	return details, nil
}
