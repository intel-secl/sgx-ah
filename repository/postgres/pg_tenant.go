/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-attestation-hub/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresTenantRepository struct {
	db *gorm.DB
}

func (r *PostgresTenantRepository) Create(t types.Tenant) (*types.Tenant, error) {
	log.Trace("repository/postgres/pg_tenant: Create() Entering")
	defer log.Trace("repository/postgres/pg_tenant: Create() Leaving")

	err := r.db.Create(&t).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create(): failed to create Tenant")
	}
	return &t, nil
}

func (r *PostgresTenantRepository) Retrieve(t types.Tenant) (*types.Tenant, error) {
	log.Trace("repository/postgres/pg_tenant: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_tenant: Retrieve() Leaving")

	var s types.Tenant
	err := r.db.Where(&t).First(&s).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve(): failed to retrieve Tenant")
	}
	return &s, nil
}

func (r *PostgresTenantRepository) RetrieveAll(t types.Tenant) (types.Tenants, error) {
	log.Trace("repository/postgres/pg_tenant: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_tenant: RetrieveAll() Leaving")

	var ts types.Tenants
	err := r.db.Where(&t).Find(&ts).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to retrieve all Tenants")
	}
	return ts, nil
}

func (r *PostgresTenantRepository) RetrieveAllActiveTenants() (types.Tenants, error) {
	log.Trace("repository/postgres/pg_tenant: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_tenant: RetrieveAll() Leaving")

	var ts types.Tenants
	err := r.db.Where("deleted = false").Find(&ts).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to retrieve all Tenants")
	}
	slog.WithField("db qes", ts).Trace("RetrieveAll")
	return ts, nil
}

func (r *PostgresTenantRepository) Update(t types.Tenant) (*types.Tenant, error) {
	log.Trace("repository/postgres/pg_tenant: Update() Entering")
	defer log.Trace("repository/postgres/pg_tenant: Update() Leaving")

	if err := r.db.Save(&t).Error; err != nil {
		return nil, errors.Wrap(err, "Update(): failed to update Tenant")
	}
	return &t, nil
}

func (r *PostgresTenantRepository) Delete(t types.Tenant) error {
	log.Trace("repository/postgres/pg_tenant: Delete() Entering")
	defer log.Trace("repository/postgres/pg_tenant: Delete() Leaving")

	if err := r.db.Delete(&t).Error; err != nil {
		return errors.Wrap(err, "Delete(): failed to delete Tenant")
	}
	return nil
}
