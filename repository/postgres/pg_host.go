/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/shub/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresHostRepository struct {
	db *gorm.DB
}

func (r *PostgresHostRepository) Create(h types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: Create() Entering")
	defer log.Trace("repository/postgres/pg_host: Create() Leaving")

	err := r.db.Create(&h).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create(): failed to create Host")
	}
	return &h, nil
}

func (r *PostgresHostRepository) Retrieve(h types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host: Retrieve() Leaving")

	var p types.Host
	err := r.db.Where(&h).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve(): failed to retrieve Host")
	}
	return &p, nil
}

func (r *PostgresHostRepository) RetrieveActiveHostByHUUID(h types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: RetrieveActiveHostByHUUID() Entering")
	defer log.Trace("repository/postgres/pg_host: RetrieveActiveHostByHUUID() Leaving")

	var p types.Host
	err := r.db.Where("deleted = (?) and hardware_uuid = (?)", false, h.HardwareUUID).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveActiveHostByHUUID(): failed to retrieve active Host")
	}
	return &p, nil
}

func (r *PostgresHostRepository) RetrieveAll(h types.Host) (types.Hosts, error) {
	log.Trace("repository/postgres/pg_host: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host: RetrieveAll() Leaving")

	var hs types.Hosts
	err := r.db.Where(&h).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to retrieve all Hosts")
	}
	return hs, nil
}

func (r *PostgresHostRepository) Update(h types.Host) error {
	log.Trace("repository/postgres/pg_host: Update() Entering")
	defer log.Trace("repository/postgres/pg_host: Update() Leaving")

	if err := r.db.Save(&h).Error; err != nil {
		return errors.Wrap(err, "Update(): failed to update Host")
	}
	return nil
}

func (r *PostgresHostRepository) Delete(h types.Host) error {
	log.Trace("repository/postgres/pg_host: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host: Delete() Leaving")

	if err := r.db.Delete(&h).Error; err != nil {
		return errors.Wrap(err, "Update(): failed to delete Host")
	}
	return nil
}
