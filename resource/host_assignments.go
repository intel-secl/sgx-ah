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
	"intel/isecl/lib/common/v2/log/message"
	"intel/isecl/lib/common/v2/validation"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
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

func SGXHostTenantMapping(r *mux.Router, db repository.SAHDatabase) {

	r.Handle("/host-assignments", handlers.ContentTypeHandler(createHostTenantMapping(db), "application/json")).Methods("POST")
	r.Handle("/host-assignments/{id}", getHostTenantMapping(db)).Methods("GET")
	r.Handle("/host-assignments", queryHostTenantMappings(db)).Methods("GET")
	r.Handle("/host-assignments/{id}", handlers.ContentTypeHandler(updateHostTenantMappings(db), "application/json")).Methods("PUT")
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

func createMapping(db repository.SAHDatabase, input HostTenantMappingRequest) ([]TenantHostMapping, error) {

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
	return mappingResponse.Mapping, nil
}

func createHostTenantMapping(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: createHostTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: createHostTenantMapping() Leaving")

		err := AuthorizeEndpoint(r, constants.TenantManagerGroupName, true)
		if err != nil {
			return err
		}

		var input HostTenantMappingRequest

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&input)
		if err != nil {
			log.WithError(err).Info("createHostTenantMapping() Error decoding request input")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if input.TenantId == "" {
			return &resourceError{Message: "tenant uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		if input.HardwareUUID == nil || len(input.HardwareUUID) == 0 {
			return &resourceError{Message: "hardware uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		validationErr := validation.ValidateUUIDv4(input.TenantId)
		if validationErr != nil {
			log.WithError(validationErr).WithField("tenant id", input.TenantId).Info("createHostTenantMapping() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		for _, huuid := range input.HardwareUUID {
			validationErr = validation.ValidateHardwareUUID(huuid)
			if validationErr != nil {
				log.WithError(validationErr).WithField("tenant id", input.TenantId).Info("createHostTenantMapping() Error validating host hardware UUID")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		mappingRes, err := createMapping(db, input)
		if err != nil {
			return err
		}

		mappingResponse := HostTenantMappingResponse {
			Mapping:mappingRes,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201
		err = json.NewEncoder(w).Encode(mappingResponse)
		if err != nil {
			log.WithError(err).Errorf("resource/host_assignments: createHostTenantMapping() %s : Unexpectedly failed to encode create mapping response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to create mapping - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}

func getHostTenantMapping(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/host_assignments: getHostTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: getHostTenantMapping() Leaving")

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/host_assignments: getHostTenantMapping() Error validating mapping Id")
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

func queryHostTenantMappings(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: queryHostTenantMappings() Entering")
		defer log.Trace("resource/host_assignments: queryHostTenantMappings() Leaving")

		log.WithField("query", r.URL.Query()).Trace("query mappings")
		tenantUUID := r.URL.Query().Get("tenant_id")
		hardwareUUID := r.URL.Query().Get("host_hardware_uuid")

		if len(tenantUUID) != 0 {
			validationErr := validation.ValidateUUIDv4(tenantUUID)
			if validationErr != nil {
				log.WithError(validationErr).WithField("tenant id", tenantUUID).Info("resource/host_assignments: queryHostTenantMappings() Error validating tenant Id")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		if len(hardwareUUID) != 0 {
			validationErr := validation.ValidateHardwareUUID(hardwareUUID)
			if validationErr != nil {
				log.WithError(validationErr).WithField("hardware uuid", hardwareUUID).Info("resource/host_assignments: queryHostTenantMappings() Error validating hardware uuid")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.HostTenantMapping{
			TenantUUID:       tenantUUID,
			HostHardwareUUID: hardwareUUID,
		}

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

func updateMapping(db repository.SAHDatabase, input HostTenantMappingRequest, id string, mapping *types.HostTenantMapping) ([]TenantHostMapping, error) {

	log.Trace("resource/host_assignments: updateMapping() Entering")
	defer log.Trace("resource/host_assignments: updateMapping() Leaving")

	var mappingResponse HostTenantMappingResponse
	_, err := db.TenantRepository().Retrieve(types.Tenant{Id: input.TenantId})
	if err != nil {
		log.WithError(err).WithField("id", input.TenantId).Info("resource/host_assignments: updateMapping() Tenant does not exist with id provided")
		return nil, &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
	}

	uniqueHuuIdList := uniqueHostHardwareIDs(input.HardwareUUID)

	for _, huuId := range uniqueHuuIdList {
		_, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: huuId})
		if err != nil {
			log.WithError(err).WithField("hardwareUUID", huuId).Info("resource/host_assignments: updateMapping() Host does not exist with hardware id provided")
			return nil, &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}
		hostTenantMapping := types.HostTenantMapping{
			Id:               id,
			HostHardwareUUID: huuId,
			TenantUUID:       input.TenantId,
			CreatedTime:      mapping.CreatedTime,
			UpdatedTime:      time.Now(),
		}
		mappingCreated, err := db.HostTenantMappingRepository().Update(hostTenantMapping)
		if err != nil {
			return nil, errors.Wrap(err, "resource/host_assignments: updateMapping() Error while caching host tenant mapping information")
		}
		mapping := TenantHostMapping{
			MappingId:    mappingCreated.Id,
			TenantId:     input.TenantId,
			HardwareUUID: huuId,
		}
		mappingResponse.Mapping = append(mappingResponse.Mapping, mapping)
	}
	return mappingResponse.Mapping, nil
}

func updateHostTenantMappings(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: updateHostTenantMappings() Entering")
		defer log.Trace("resource/host_assignments: updateHostTenantMappings() Leaving")

		var mapping HostTenantMappingRequest

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/host_assignments: updateHostTenantMappings() Error validating mapping Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}
		m, err := db.HostTenantMappingRepository().Retrieve(types.HostTenantMapping{Id: id})
		if m == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("resource/host_assignments: updateHostTenantMappings() mapping with specified id does not exist")
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if m.Deleted == true {
			log.Errorf("resource/host_assignments: updateHostTenantMappings() mapping with id %s was deleted", id)
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&mapping)
		if err != nil {
			log.WithError(err).Info("resource/host_assignments: updateHostTenantMappings() Error decoding request input")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if mapping.TenantId == "" {
			return &resourceError{Message: "tenant uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		if mapping.HardwareUUID == nil || len(mapping.HardwareUUID) == 0 {
			return &resourceError{Message: "hardware uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		validationErr = validation.ValidateUUIDv4(mapping.TenantId)
		if validationErr != nil {
			log.WithError(validationErr).WithField("tenant id", mapping.TenantId).Info("resource/host_assignments: updateHostTenantMappings() Error validating tenant Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		for _, huuid := range mapping.HardwareUUID {
			validationErr = validation.ValidateHardwareUUID(huuid)
			if validationErr != nil {
				log.WithError(validationErr).WithField("tenant id", mapping.TenantId).Info("resource/host_assignments: updateHostTenantMappings() Error validating host hardware UUID")
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}
		mappingRes, err := updateMapping(db, mapping, id, m)
		if err != nil {
			return err
		}

		mappingResponse := HostTenantMappingResponse {
			Mapping:mappingRes,
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(mappingResponse)
		if err != nil {
			log.WithError(err).Errorf("resource/host_assignments: updateHostTenantMappings() %s : Unexpectedly failed to encode update mapping response to JSON", message.AppRuntimeErr)
			log.Tracef("%+v", err)
			return &resourceError{Message: "Failed to update mapping - JSON encode failed", StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}

func deleteTenantMapping(db repository.SAHDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		log.Trace("resource/host_assignments: deleteTenantMapping() Entering")
		defer log.Trace("resource/host_assignments: deleteTenantMapping() Leaving")

		id := mux.Vars(r)["id"]
		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			log.WithError(validationErr).WithField("id", id).Info("resource/host_assignments: deleteTenantMapping() Error validating host tenant mapping Id")
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