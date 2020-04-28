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
	"intel/isecl/lib/common/v2/validation"
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
	log.Trace("resource/host_assignments: SGXHostTenantMapping() Entering")
	defer log.Trace("resource/host_assignments: SGXHostTenantMapping() Leaving")

	r.Handle("/host-assignments", handlers.ContentTypeHandler(createHostTenantMapping(db), "application/json")).Methods("POST")
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
		log.Error("resource/host_assignments: createMapping() Tenant does not exist with id :", input.TenantId)
		return nil, &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
	}

	uniqueHuuIdList := uniqueHostHardwareIDs(input.HardwareUUID)

	for _, huuId := range uniqueHuuIdList {
		_, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: huuId})
		if err != nil {
			log.Error("resource/host_assignments: createMapping() Host does not exist with id :", huuId)
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

		var input HostTenantMappingRequest

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&input)
		if err != nil {
			log.Error("resource/host_assignments: createHostTenantMapping() Error decoding request input" + err.Error())
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if input.TenantId == "" {
			return &resourceError{Message: "tenant uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		if input.HardwareUUID == nil || len(input.HardwareUUID) == 0{
			return &resourceError{Message: "hardware uuid information is mandatory", StatusCode: http.StatusBadRequest}
		}

		validationErr := validation.ValidateUUIDv4(input.TenantId)
		if validationErr != nil {
			log.Error("resource/host_assignments: createHostTenantMapping() Error validating tenant Id" + validationErr.Error())
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		for _, huuid := range input.HardwareUUID {
			validationErr = validation.ValidateHardwareUUID(huuid)
			if validationErr != nil {
				log.Error("resource/host_assignments: createHostTenantMapping() Error validating host hardware UUID" + validationErr.Error())
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		mappingRes, err := createMapping(db, input)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201
		err = json.NewEncoder(w).Encode(mappingRes)
		if err != nil {
			return err
		}
		return nil
	}
}
