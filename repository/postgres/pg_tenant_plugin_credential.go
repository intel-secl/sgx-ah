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

type PostgresTenantPluginCredentialRepository struct {
	db *gorm.DB
}

func (r *PostgresTenantPluginCredentialRepository) Create(p types.TenantPluginCredential) (*types.TenantPluginCredential, error) {
	log.Trace("repository/postgres/pg_tenant_plugin_credential: Create() Entering")
	defer log.Trace("repository/postgres/pg_tenant_plugin_credential: Create() Leaving")

	uuid, err := repository.UUID()
	if err == nil {
		p.Id = uuid
	} else {
		return &p, errors.Wrap(err, "Create(): failed to get UUID")
	}
	err = r.db.Create(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create(): Failed to create Tenant Plugin Credential")
	}
	return &p, nil
}

func (r *PostgresTenantPluginCredentialRepository) Retrieve(p types.TenantPluginCredential) (*types.TenantPluginCredential, error) {
	log.Trace("repository/postgres/pg_tenant_plugin_credential: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_tenant_plugin_credential: Retrieve() Leaving")

	var c types.HostTenantMapping
	err := r.db.Where(&p).First(&c).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve(): Failed to retrieve Tenant Plugin Credential")
	}
	return &p, nil
}

func (r *PostgresTenantPluginCredentialRepository) RetrieveAll(p types.TenantPluginCredential) (types.TenantPluginCredentials, error) {
	log.Trace("repository/postgres/pg_tenant_plugin_credential: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_tenant_plugin_credential: RetrieveAll() Leaving")

	var ps types.TenantPluginCredentials
	err := r.db.Where(&p).Find(&ps).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to retrieve all Tenant Plugin Credentials")
	}
	return ps, nil
}

func (r *PostgresTenantPluginCredentialRepository) Update(p types.TenantPluginCredential) error {
	log.Trace("repository/postgres/pg_tenant_plugin_credential: Update() Entering")
	defer log.Trace("repository/postgres/pg_tenant_plugin_credential: Update() Leaving")

	if err := r.db.Save(&p).Error; err != nil {
		return errors.Wrap(err, "Update(): Failed to Update Tenant Plugin Credential")
	}
	return nil
}

func (r *PostgresTenantPluginCredentialRepository) Delete(p types.TenantPluginCredential) error {
	log.Trace("repository/postgres/pg_tenant_plugin_credential: Delete() Entering")
	defer log.Trace("repository/postgres/pg_tenant_plugin_credential: Delete() Leaving")

	if err := r.db.Delete(&p).Error; err != nil {
		return errors.Wrap(err, "Delete(): Failed to Delete Tenant Plugin Credential")
	}
	return nil
}

