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
	"intel/isecl/lib/common/v3/log/message"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/lib/common/v3/validation"
	"intel/isecl/shub/constants"
	"intel/isecl/shub/repository"
	"intel/isecl/shub/types"
	"net/http"
	"time"
)

type HostTenantMappingRequest struct {
	TenantId     string   `json:"tenant_id"`
	HardwareUUID []string `json:"hardware_uuids"`
}

type TenantHostMapping struct {
	MappingId    string `json:"mapping_id"`
	TenantId     string `json:"tenant_id"`
	HardwareUUID string `json:"hardware_uuid"`
}

type HostTenantMappingResponse struct {
	Mapping []TenantHostMapping `json:"mappings"`
}

func SGXHostTenantMapping(r *mux.Router, db repository.SHUBDatabase) {

	r.Handle("/host-assignments", handlers.ContentTypeHandler(createHostTenantMapping(db), "application/json")).Methods("POST")
	r.Handle("/host-assignments/{id}", getHostTenantMapping(db)).Methods("GET")
	r.Handle("/host-assignments", queryHostTenantMappings(db)).Methods("GET")
	r.Handle("/host-assignments/{id}", deleteTenantMapping(db)).Methods("DELETE")
}

func uniqueHostHardwareIDs(huuIds []string) []string {
	log.Trace("resource/host_assignments: uniqueHostHardwareIDs() Entering")
	defer log.Trace("resource/host_assignments: uniqueHostHardwareIDs() Leaving")

	keys := make(map[string]bool)
	var huuIdList []string

	for _, huuId := range huuIds {
		if _, value := keys[huuId]; !value {
			keys[huuId] = true
			huuIdList = append(huuIdList, huuId)
		}
	}
	return huuIdList
}

func createOrUpdateMapping(db repository.SHUBDatabase, input HostTenantMappingRequest) ([]TenantHostMapping, error) {

	log.Trace("resource/host_assignments: createMapping() Entering")
	defer log.Trace("resource/host_assignments: createMapping() Leaving")

	var mappingResponse HostTenantMappingResponse
	_, err := db.TenantRepository().Retrieve(types.Tenant{Id: input.TenantId})
	if err != nil {
		log.WithError(err).WithField("id", input.TenantId).Info("createMapping() Tenant does not exist with id provided")
		return nil, &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
	}

	uniqueHuuIdList := uniqueHostHardwareIDs(input.HardwareUUID)

	for _, huuId := range uniqueHuuIdList {
		_, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: huuId})
		if err != nil {
			log.WithError(err).WithField("hardwareUUID", huuId).Info("createMapping() Host does not exist with hardware id provided")
			return nil, &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}

		filter := types.HostTenantMapping{
			TenantUUID:       input.TenantId,
			HostHardwareUUID: huuId,
		}

		// Retrieve mapping by filter criteria, update the same if it exists else create a new mapping
		existingMap, err := db.HostTenantMappingRepository().Retrieve(filter)
		if existingMap != nil && err == nil {
			log.Debugf("Mapping between tenant %s and host hardware uuid %s already exists", existingMap.TenantUUID, existingMap.HostHardwareUUID)
			if existingMap.Deleted == true {
				log.Debugf("The mapping %s was deleted earlier. Reactivating it instead of creating a new one", existingMap.Id)
				hostTenantMap := types.HostTenantMapping{
					Id:               existingMap.Id,
					HostHardwareUUID: existingMap.HostHardwareUUID,
					TenantUUID:       existingMap.TenantUUID,
					CreatedTime:      existingMap.CreatedTime,
					UpdatedTime:      time.Now(),
					Deleted:          false,
				}
				_, err := db.HostTenantMappingRepository().Update(hostTenantMap)
				if err != nil {
					return nil, errors.Wrap(err, "resource/host_assignments: createMapping() Error while updating host tenant mapping information")
				}
			} else {
				log.Debugf("Mapping %s is still active. Not creating a new entry", existingMap.Id)
			}
			mapping := TenantHostMapping{
				MappingId:    existingMap.Id,
				TenantId:     input.TenantId,
				HardwareUUID: huuId,
			}
			mappingResponse.Mapping = append(mappingResponse.Mapping, mapping)
		} else {
			hostTenantMapping := types.HostTenantMapping{
				HostHardwareUUID: huuId,
				TenantUUID:       input.TenantId,
				CreatedTime:      time.Now(),
				UpdatedTime:      time.Now(),
			}
			mappingCreated, err := db.HostTenantMappingRepository().Create(hostTenantMapping)
			if err != nil {
				return nil, errors.Wrap(err, "resource/host_assignments: createMapping() Error while caching host tenant mapping information")
			}
			mapping := TenantHostMapping{
				MappingId:    mappingCreated.Id,
				TenantId:     input.TenantId,
				HardwareUUID: huuId,
			}
			mappingResponse.Mapping = append(mappingResponse.Mapping, mapping)
		}
	}
	return mappingResponse.Mapping, nil
}

func createHostTenantMapping(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: createHostTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: createHostTenantMapping() Leaving")

		err := authorizeEndpoint(r, constants.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		var input HostTenantMappingRequest

		if r.ContentLength == 0 {
			slog.Error("resource/host_assignments: createHostTenantMapping() The request body was not provided")
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&input)
		if err != nil {
			slog.WithError(err).Errorf("resource/host_assignments: createHostTenantMapping() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if input.TenantId == "" {
			slog.Error("resource/host_assignments: createHostTenantMapping() Missing mandatory configuration tenant Id")
			return &resourceError{Message: "tenant uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		if input.HardwareUUID == nil || len(input.HardwareUUID) == 0 {
			slog.Error("resource/host_assignments: createHostTenantMapping() Missing mandatory configuration hardware UUID")
			return &resourceError{Message: "hardware uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		validationErr := validation.ValidateUUIDv4(input.TenantId)
		if validationErr != nil {
			slog.WithError(validationErr).WithField("tenant id", input.TenantId).Info("createHostTenantMapping() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		for _, huuid := range input.HardwareUUID {
			validationErr = validation.ValidateHardwareUUID(huuid)
			if validationErr != nil {
				slog.WithError(validationErr).WithField("tenant id", input.TenantId).Info("createHostTenantMapping() Error validating host hardware UUID")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		mappingRes, err := createOrUpdateMapping(db, input)
		if err != nil {
			return err
		}

		mappingResponse := HostTenantMappingResponse{
			Mapping: mappingRes,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201
		err = json.NewEncoder(w).Encode(mappingResponse)
		if err != nil {
			log.WithError(err).Errorf("resource/host_assignments: createHostTenantMapping() %s : Unexpectedly failed to encode create mapping response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to create mapping - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.Info("resource/host_assignments: createHostTenantMapping() Mapping created by:", r.RemoteAddr)
		return nil
	}
}

func getHostTenantMapping(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/host_assignments: getHostTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: getHostTenantMapping() Leaving")

		err := authorizeEndpoint(r, constants.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			slog.WithError(validationErr).WithField("id", id).Info("resource/host_assignments: getHostTenantMapping() Error validating mapping Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		tenantMapping, err := db.HostTenantMappingRepository().Retrieve(types.HostTenantMapping{Id: id})
		if tenantMapping == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/host_assignments: getHostTenantMapping() mapping with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if tenantMapping.Deleted == true {
			log.Errorf("resource/host_assignments: getHostTenantMapping() mapping with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tenantMapping)
		if err != nil {
			log.WithError(err).Errorf("resource/host_assignments: getHostTenantMapping() %s : Unexpectedly failed to encode retrieve mapping response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to retrieve mapping - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.WithField("tenantMapping", tenantMapping).Info("mapping retrieved by:", r.RemoteAddr)
		return nil
	}
}

func queryHostTenantMappings(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: queryHostTenantMappings() Entering")
		defer log.Trace("resource/host_assignments: queryHostTenantMappings() Leaving")

		err := authorizeEndpoint(r, constants.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		log.WithField("query", r.URL.Query()).Trace("query mappings")
		tenantUUID := r.URL.Query().Get("tenant_id")
		hardwareUUID := r.URL.Query().Get("host_hardware_uuid")

		if len(tenantUUID) != 0 {
			validationErr := validation.ValidateUUIDv4(tenantUUID)
			if validationErr != nil {
				slog.WithError(validationErr).WithField("tenant id", tenantUUID).Info("resource/host_assignments: queryHostTenantMappings() Error validating tenant Id query param")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		if len(hardwareUUID) != 0 {
			validationErr := validation.ValidateHardwareUUID(hardwareUUID)
			if validationErr != nil {
				slog.WithError(validationErr).WithField("hardware uuid", hardwareUUID).Info("resource/host_assignments: queryHostTenantMappings() Error validating hardware uuid query param")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.HostTenantMapping{
			TenantUUID:       tenantUUID,
			HostHardwareUUID: hardwareUUID,
		}

		// Retrieve mappings based on the filter criteria
		mappings, err := db.HostTenantMappingRepository().RetrieveAll(filter)
		if len(mappings) == 0 || err != nil {
			log.WithError(err).Info("resource/host_assignments: queryHostTenantMappings() Mappings do not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(mappings)
		if err != nil {
			log.WithError(err).Errorf("resource/host_assignments: queryHostTenantMappings() %s : Unexpectedly failed to encode query mapping response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to search mapping - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("Return tenant query to: %s", r.RemoteAddr)
		return nil
	}
}

func deleteTenantMapping(db repository.SHUBDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: deleteTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: deleteTenantMapping() Leaving")

		err := authorizeEndpoint(r, constants.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			slog.WithError(validationErr).WithField("id", id).Info("resource/host_assignments: deleteTenantMapping() Error validating host tenant mapping Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		tenantMapping, err := db.HostTenantMappingRepository().Retrieve(types.HostTenantMapping{Id: id})
		if tenantMapping == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/host_assignments: deleteTenantMapping() mapping with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if tenantMapping.Deleted == true {
			log.Errorf("resource/host_assignments: deleteTenantMapping() tenant mapping with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		// Instead of deleting the mapping from the DB, update deleted field to true
		tenantMappingInput := types.HostTenantMapping{
			Id:               tenantMapping.Id,
			HostHardwareUUID: tenantMapping.HostHardwareUUID,
			TenantUUID:       tenantMapping.TenantUUID,
			CreatedTime:      tenantMapping.CreatedTime,
			UpdatedTime:      time.Now(),
			Deleted:          true,
		}

		_, err = db.HostTenantMappingRepository().Update(tenantMappingInput)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.WithField("tenantMapping", tenantMapping).Info("Tenant deleted by:", r.RemoteAddr)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
