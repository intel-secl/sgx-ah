/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	consts "intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
	"net/http"
	"strings"
	"time"
)

type PluginProperty struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Plugin struct {
	PluginName string           `json:"name"`
	Properties []PluginProperty `json:"properties"`
}

type Tenant struct {
	TenantName string    `json:"name"`
	Plugins    []*Plugin `json:"plugins"`
}

func SGXTenantRegister(r *mux.Router, db repository.SAHDatabase) {
	log.Trace("resource/tenants: SGXTenantRegister() Entering")
	defer log.Trace("resource/tenants: SGXTenantRegister() Leaving")

	r.Handle("/tenants", handlers.ContentTypeHandler(registerTenant(db), "application/json")).Methods("POST")
}

func extractCredentialFromTenant(tenant Tenant) map[string][]PluginProperty {
	log.Trace("resource/tenants: extractCredentialFromTenant() Entering")
	defer log.Trace("resource/tenants: extractCredentialFromTenant() Leaving")

	pluginCredentialsMap := make(map[string][]PluginProperty)
	plugins := tenant.Plugins

	log.Debug("Extracting credentials from tenant")
	for _, plugin := range plugins {
		if strings.EqualFold(plugin.PluginName, consts.OpenStackPlugin) {
			credentials := make([]PluginProperty, 0)
			for _, property := range plugin.Properties {
				if (property.Key == consts.NovaPluginUserName) || (property.Key == consts.NovaPluginUserPassword) {
					credentials = append(credentials, property)
					pluginCredentialsMap[plugin.PluginName] = credentials
				}
			}
		}
		if strings.EqualFold(plugin.PluginName, consts.KubernetesPlugin) {
			credentials := make([]PluginProperty, 0)
			for _, property := range plugin.Properties {
				if (property.Key == consts.KubernetesClientKeystorePassword) || (property.Key == consts.KubernetesServerKeystorePassword) {
					credentials = append(credentials, property)
					pluginCredentialsMap[plugin.PluginName] = credentials
				}
			}
		}
	}
	return pluginCredentialsMap
}

func removeProperty(properties []PluginProperty, index int) []PluginProperty {
	log.Trace("resource/tenants: removeProperty() Entering")
	defer log.Trace("resource/tenants: removeProperty() Leaving")

	return append(properties[:index], properties[index+1:]...)
}

func removeCredentialFromTenant(tenant Tenant) {
	log.Trace("resource/tenants: removeCredentialFromTenant() Entering")
	defer log.Trace("resource/tenants: removeCredentialFromTenant() Leaving")

	plugins := tenant.Plugins

	log.Debug("Removing credentials from tenant")
	for _, plugin := range plugins {
		if strings.EqualFold(plugin.PluginName, consts.OpenStackPlugin) {
			for index := 0; index < len(plugin.Properties); index++ {
				if (plugin.Properties[index].Key == consts.NovaPluginUserName) || (plugin.Properties[index].Key == consts.NovaPluginUserPassword) {
					plugin.Properties = removeProperty(plugin.Properties, index)
					index--
				}
			}
		}
		if strings.EqualFold(plugin.PluginName, consts.KubernetesPlugin) {
			for index := 0; index < len(plugin.Properties); index++ {
				if (plugin.Properties[index].Key == consts.KubernetesClientKeystorePassword) || (plugin.Properties[index].Key == consts.KubernetesServerKeystorePassword) {
					plugin.Properties = removeProperty(plugin.Properties, index)
					index--
				}
			}
		}
	}
}

func createTenantPluginCredential(db repository.SAHDatabase, tenantInput *types.Tenant, pluginCredentialsMap map[string][]PluginProperty) error {
	log.Trace("resource/tenant:createTenantPluginCredential() Entering")
	defer log.Trace("resource/tenant:createTenantPluginCredential() Leaving")

	for pluginName, pluginValue := range pluginCredentialsMap {
		pluginValueJSON, err := json.Marshal(pluginValue)
		if err != nil {
			return errors.Wrap(err, "resource/tenant:createTenantPluginCredential() failed to marshal tenant data to JSON")
		}
		pluginValueStr := string(pluginValueJSON)
		AhTenantPluginCredential := types.TenantPluginCredential{
			TenantUUID:  tenantInput.Id,
			PluginName:  pluginName,
			TenantName:  tenantInput.TenantName,
			Credential:  pluginValueStr,
			CreatedTime: time.Now(),
		}
		_, err = db.TenantPluginCredentialRepository().Create(AhTenantPluginCredential)
		if err != nil {
			return errors.Wrap(err, "resource/tenant:createTenantPluginCredential() Error while caching Plugin Credentials")
		}
	}
	return nil
}

func registerTenant(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/tenant:registerTenant() Entering")
		defer log.Trace("resource/tenant:registerTenant() Leaving")

		var tenant Tenant

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&tenant)
		if err != nil {
			log.WithError(err).Info("registerTenant() Error decoding request input")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		validateResult := ValidateInput(tenant)
		if validateResult != "" {
			log.Error("resource/tenant:registerTenant() input validation failed")
			return &resourceError{Message: validateResult, StatusCode: http.StatusBadRequest}
		}

		pluginCredentialsMap := extractCredentialFromTenant(tenant)
		removeCredentialFromTenant(tenant)

		tenantJSON, err := json.Marshal(tenant)
		if err != nil {
			log.WithError(err).Info("registerTenant() failed to marshal tenant data to JSON")
			return errors.New("resource/tenant:registerTenant() failed to marshal tenant data to JSON")
		}
		tenantStr := string(tenantJSON)
		tenantInput := types.Tenant{
			TenantName:  tenant.TenantName,
			Config:      tenantStr,
			CreatedTime: time.Now(),
			UpdatedTime: time.Now(),
		}
		created, err := db.TenantRepository().Create(tenantInput)
		if err != nil {
			return errors.New("resource/tenant:registerTenant() Error while caching tenant information")
		}

		err = createTenantPluginCredential(db, created, pluginCredentialsMap)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201
		err = json.NewEncoder(w).Encode(created)
		if err != nil {
			return err
		}
		return nil
	}
}
