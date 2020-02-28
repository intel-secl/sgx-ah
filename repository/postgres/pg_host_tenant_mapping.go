/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresHostTenantMappingRepository struct {
	db *gorm.DB
}

func (r *PostgresHostTenantMappingRepository) Create(m types.HostTenantMapping) (*types.HostTenantMapping, error) {
	log.Trace("repository/postgres/pg_host_tenant_mapping: Create() Entering")
	defer log.Trace("repository/postgres/pg_host_tenant_mapping: Create() Leaving")

	uuid, err := repository.UUID()
	if err == nil {
		m.Id = uuid
	} else {
		return &m, errors.Wrap(err, "Create(): failed to get UUID")
	}
	err = r.db.Create(&m).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create(): failed to create Host Tenant Mapping")
	}
	return &m, nil
}

func (r *PostgresHostTenantMappingRepository) Retrieve(m types.HostTenantMapping) (*types.HostTenantMapping, error) {
	log.Trace("repository/postgres/pg_host_tenant_mapping: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host_tenant_mapping: Retrieve() Leaving")

	var p types.HostTenantMapping
	err := r.db.Where(&m).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve(): failed to Retrieve Host Tenant Mapping")
	}
	return &m, nil
}

func (r *PostgresHostTenantMappingRepository) RetrieveAll(m types.HostTenantMapping) (types.HostTenantMappings, error) {
	log.Trace("repository/postgres/pg_host_tenant_mapping: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host_tenant_mapping: RetrieveAll() Leaving")

	var ms types.HostTenantMappings
	err := r.db.Where(&m).Find(&ms).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to retrieve all Host Tenant Mappings")
	}
	return ms, nil
}

func (r *PostgresHostTenantMappingRepository) Update(m types.HostTenantMapping) error {
	log.Trace("repository/postgres/pg_host_tenant_mapping: Update() Entering")
	defer log.Trace("repository/postgres/pg_host_tenant_mapping: Update() Leaving")

	if err := r.db.Save(&m).Error; err != nil {
		return errors.Wrap(err, "Update(): failed to update Host Tenant Mapping")
	}
	return nil
}

func (r *PostgresHostTenantMappingRepository) Delete(m types.HostTenantMapping) error {
	log.Trace("repository/postgres/pg_host_tenant_mapping: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host_tenant_mapping: Delete() Leaving")

	if err := r.db.Delete(&m).Error; err != nil {
		return errors.Wrap(err, "Delete(): failed to delete Host Tenant Mapping")
	}
	return nil
}

