/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v2/log/message"
	"intel/isecl/lib/common/v2/validation"
	consts "intel/isecl/shub/constants"
	"intel/isecl/shub/repository"
	"intel/isecl/shub/types"
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
	TenantId        string    `json:"id,omitempty"`
	TenantName      string    `json:"name"`
	TenantDeleted   bool      `json:"deleted"`
	Plugins         []*Plugin `json:"plugins"`
}

func SGXTenantRegister(r *mux.Router, db repository.SHUBDatabase) {

	r.Handle("/tenants", handlers.ContentTypeHandler(registerTenant(db), "application/json")).Methods("POST")
	r.Handle("/tenants/{id}", getTenant(db)).Methods("GET")
	r.Handle("/tenants", queryTenants(db)).Methods("GET")
	r.Handle("/tenants/{id}", handlers.ContentTypeHandler(updateTenant(db), "application/json")).Methods("PUT")
	r.Handle("/tenants/{id}", deleteTenant(db)).Methods("DELETE")
}

func extractCredentialFromTenant(tenant Tenant) map[string][]PluginProperty {
	log.Trace("resource/tenants: extractCredentialFromTenant() Entering")
	defer log.Trace("resource/tenants: extractCredentialFromTenant() Leaving")

	pluginCredentialsMap := make(map[string][]PluginProperty)
	plugins := tenant.Plugins

	log.Debug("resource/tenants: extractCredentialFromTenant() Extracting credentials from tenant")
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

	log.Debug("resource/tenants: removeCredentialFromTenant() Removing credentials from tenant")
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

func createTenantPluginCredential(db repository.SHUBDatabase, tenantInput *types.Tenant, pluginCredentialsMap map[string][]PluginProperty) error {
	log.Trace("resource/tenants:createTenantPluginCredential() Entering")
	defer log.Trace("resource/tenants:createTenantPluginCredential() Leaving")

	for pluginName, pluginValue := range pluginCredentialsMap {
		pluginValueJSON, err := json.Marshal(pluginValue)
		if err != nil {
			return errors.Wrap(err, "resource/tenants:createTenantPluginCredential() failed to marshal tenant data to JSON")
		}
		pluginValueStr := string(pluginValueJSON)
		SHubTenantPluginCredential := types.TenantPluginCredential{
			TenantUUID:  tenantInput.Id,
			PluginName:  pluginName,
			TenantName:  tenantInput.TenantName,
			Credential:  pluginValueStr,
			CreatedTime: time.Now(),
		}
		_, err = db.TenantPluginCredentialRepository().Create(SHubTenantPluginCredential)
		if err != nil {
			return errors.Wrap(err, "resource/tenants:createTenantPluginCredential() Error while caching Plugin Credentials")
		}
	}
	return nil
}

func deleteTenantPluginCredential(db repository.SHUBDatabase, updatedTenant *types.Tenant) error {
	log.Trace("resource/tenants:deleteTenantPluginCredential() Entering")
	defer log.Trace("resource/tenants:deleteTenantPluginCredential() Leaving")

	tenantPluginCredentials, err := db.TenantPluginCredentialRepository().RetrieveByTenantId(updatedTenant.Id)
	if err != nil {
		return errors.Wrap(err,"resource/tenants:deleteTenantPluginCredential() Error in retrieving plugin credentials for provided tenant")
	}
	for _, tenantPluginCredential := range tenantPluginCredentials {
		err := db.TenantPluginCredentialRepository().Delete(tenantPluginCredential)
		if err != nil {
			return errors.Wrap(err, "resource/tenants:deleteTenantPluginCredential() Error in deleting plugin credentials")
		}
	}
	return nil
}

func registerTenant(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/tenants:registerTenant() Entering")
		defer log.Trace("resource/tenants:registerTenant() Leaving")

		err := AuthorizeEndpoint(r, consts.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		var tenant Tenant

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&tenant)
		if err != nil {
			log.WithError(err).Info("resource/tenants:registerTenant() Error decoding request input")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		validateResult := ValidateInput(tenant)
		if validateResult != "" {
			log.Error("resource/tenants:registerTenant() input validation failed")
			return &resourceError{Message: validateResult, StatusCode: http.StatusBadRequest}
		}

		pluginCredentialsMap := extractCredentialFromTenant(tenant)
		removeCredentialFromTenant(tenant)

		tenantJSON, err := json.Marshal(tenant)
		if err != nil {
			log.WithError(err).Info("resource/tenants:registerTenant() failed to marshal tenant data to JSON")
			return errors.New("resource/tenants:registerTenant() failed to marshal tenant data to JSON")
		}
		tenantStr := string(tenantJSON)
		tenantId := uuid.New().String()
		tenantInput := types.Tenant{
			Id:          tenantId,
			TenantName:  tenant.TenantName,
			Config:      tenantStr,
			CreatedTime: time.Now(),
			UpdatedTime: time.Now(),
			Deleted:     false,
		}
		created, err := db.TenantRepository().Create(tenantInput)
		if err != nil {
			return errors.New("resource/tenants:registerTenant() Error while caching tenant information")
		}

		err = createTenantPluginCredential(db, created, pluginCredentialsMap)
		if err != nil {
			return err
		}

		tenantResponse := Tenant {
			TenantId:      created.Id,
			TenantName:    created.TenantName,
			TenantDeleted: created.Deleted,
			Plugins:       tenant.Plugins,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201
		err = json.NewEncoder(w).Encode(tenantResponse)
		if err != nil {
			log.WithError(err).Errorf("resource/tenants:registerTenant() %s : Unexpectedly failed to encode register tenant response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to register tenant - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}

func getTenant(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/tenants: getTenant() Entering")
		defer log.Trace("resource/tenants: getTenant() Leaving")

		err := AuthorizeEndpoint(r, consts.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/tenants: getTenant() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		tenant, err := db.TenantRepository().Retrieve(types.Tenant{Id: id})
		if tenant == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/tenants: getTenant() tenant with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if tenant.Deleted == true {
			log.Errorf("resource/tenants: getTenant() tenant with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}
		
		var tenantIn Tenant
		config := tenant.Config
		err = json.Unmarshal([]byte(config), &tenantIn)
		if err != nil {
			return err
		}
		response := Tenant{
			TenantId:      tenant.Id,
			TenantName:    tenantIn.TenantName,
			TenantDeleted: tenantIn.TenantDeleted,
			Plugins:       tenantIn.Plugins,
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.WithError(err).Errorf("resource/tenants:getTenant() %s : Unexpectedly failed to encode retrieve tenant response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to retrieve tenant - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.WithField("tenant", tenant).Info("Tenant retrieved by:", r.RemoteAddr)
		return nil
	}
}

func queryTenants(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/tenants:queryTenants() Entering")
		defer log.Trace("resource/tenants:queryTenants() Leaving")

		err := AuthorizeEndpoint(r, consts.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query tenants")
		tenantName := r.URL.Query().Get("nameEqualTo")

		if len(tenantName) != 0 {
			if validationErr := ValidateNameString(tenantName); validationErr != nil {
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.Tenant{
			TenantName: tenantName,
		}
		allTenants, err := db.TenantRepository().RetrieveAll(filter)
		if len(allTenants) == 0 || err != nil {
			log.WithError(err).Info("resource/tenants: queryTenants() Tenants do not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		tenants := make([]Tenant, 0)
		for _ , tenant := range allTenants {
			var tenantIn Tenant
			if tenant.Deleted == true {
				log.Debugf("resource/tenants: queryTenants() tenant with id %s was deleted, hence not returning in the results", tenant.Id)
				continue
			}

			config := tenant.Config
			err = json.Unmarshal([]byte(config), &tenantIn)
			if err != nil {
				return err
			}

			response := Tenant {
				TenantId:      tenant.Id,
				TenantName:    tenantIn.TenantName,
				TenantDeleted: tenantIn.TenantDeleted,
				Plugins:       tenantIn.Plugins,
			}
			tenants = append(tenants, response)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tenants)
		if err != nil {
			log.WithError(err).Errorf("resource/tenants:queryTenants() %s : Unexpectedly failed to encode query tenant response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to search tenant - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.WithField("tenant", tenants).Infof("Return tenant query to: %s", r.RemoteAddr)
		return nil
	}
}

func updateTenant(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/tenants:updateTenant() Entering")
		defer log.Trace("resource/tenants:updateTenant() Leaving")

		err := AuthorizeEndpoint(r, consts.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		var tenant Tenant

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/tenants: updateTenant() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}
		t, err := db.TenantRepository().Retrieve(types.Tenant{Id: id})
		if t == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/tenants: updateTenant() tenant with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if t.Deleted == true {
			log.Errorf("resource/tenants: updateTenant() tenant with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&tenant)
		if err != nil {
			log.WithError(err).Info("resource/tenants: updateTenant() Error decoding request input")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		validateResult := ValidateInput(tenant)
		if validateResult != "" {
			log.Error("resource/tenants:updateTenant() input validation failed")
			return &resourceError{Message: validateResult, StatusCode: http.StatusBadRequest}
		}

		pluginCredentialsMap := extractCredentialFromTenant(tenant)
		removeCredentialFromTenant(tenant)

		tenantJSON, err := json.Marshal(tenant)
		if err != nil {
			log.WithError(err).Info("resource/tenants:updateTenant() failed to marshal tenant data to JSON")
			return errors.New("resource/tenants:updateTenant() failed to marshal tenant data to JSON")
		}

		tenantStr := string(tenantJSON)
		tenantInput := types.Tenant{
			Id:          id,
			TenantName:  tenant.TenantName,
			Config:      tenantStr,
			CreatedTime: t.CreatedTime,
			UpdatedTime: time.Now(),
			Deleted:     false,
		}
		updatedTenant, err := db.TenantRepository().Update(tenantInput)
		if err != nil {
			log.WithError(err).Error("resource/tenants: updateTenant() Error while updating tenant information")
			return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
		}

		err = deleteTenantPluginCredential(db, updatedTenant)
		if err != nil {
			return err
		}

		err = createTenantPluginCredential(db, updatedTenant, pluginCredentialsMap)
		if err != nil {
			return err
		}

		tenantResponse := Tenant {
			TenantId:      updatedTenant.Id,
			TenantName:    updatedTenant.TenantName,
			TenantDeleted: updatedTenant.Deleted,
			Plugins:       tenant.Plugins,
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tenantResponse)
		if err != nil {
			log.WithError(err).Errorf("resource/tenants: updateTenant() %s : Unexpectedly failed to encode update tenant response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to update tenant - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.WithField("tenant", tenant).Info("Tenant updated by:", r.RemoteAddr)
		return nil
	}
}

func deleteTenant(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/tenants: deleteTenant() Entering")
		defer log.Trace("resource/tenants: deleteTenant() Leaving")

		err := AuthorizeEndpoint(r, consts.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/tenants: deleteTenant() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		tenant, err := db.TenantRepository().Retrieve(types.Tenant{Id: id})
		if tenant == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/tenants: deleteTenant() tenant with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if tenant.Deleted == true {
			log.Errorf("resource/tenants: deleteTenant() tenant with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		tenantInput := types.Tenant{
			Id:          tenant.Id,
			TenantName:  tenant.TenantName,
			Config:      tenant.Config,
			CreatedTime: tenant.CreatedTime,
			UpdatedTime: time.Now(),
			Deleted:     true,
		}

		_, err = db.TenantRepository().Update(tenantInput)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		mappings, err := db.HostTenantMappingRepository().RetrieveAll(types.HostTenantMapping{TenantUUID:tenant.Id})
		if len(mappings) == 0 || err != nil {
			log.WithError(err).Info("resource/tenants: deleteTenant() Cannot retrieve mappings of the corresponding tenant")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}
		for _, mapping := range mappings {
			tenantMappingInput := types.HostTenantMapping{
				Id:               mapping.Id,
				HostHardwareUUID: mapping.HostHardwareUUID,
				TenantUUID:       mapping.TenantUUID,
				CreatedTime:      mapping.CreatedTime,
				UpdatedTime:      time.Now(),
				Deleted:          true,
			}

			_, err = db.HostTenantMappingRepository().Update(tenantMappingInput)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}
		slog.WithField("tenant", tenant).Info("Tenant deleted by:", r.RemoteAddr)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
