/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
	 commLog "intel/isecl/lib/common/log"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

type PostgresDatabase struct {
	DB *gorm.DB
}

func (pd *PostgresDatabase) ExecuteSql(sql *string) error {
	log.Trace("repository/postgres/pg_database: ExecuteSql() Entering")
	defer log.Trace("repository/postgres/pg_database: ExecuteSql() Leaving")

	err := pd.DB.Exec(*sql).Error
	if err != nil {
		return errors.Wrap(err, "ExecuteSql: failed to execute sql")
	}
	return nil
}

func (pd *PostgresDatabase) ExecuteSqlFile(file string) error {
	log.Trace("repository/postgres/pg_database: ExecuteSqlFile() Entering")
	defer log.Trace("repository/postgres/pg_database: ExecuteSqlFile() Leaving")

	c, err := ioutil.ReadFile(file)
	if err != nil {
		return errors.Wrapf(err, "could not read sql file - %s", file)
	}
	sql := string(c)
	if err := pd.ExecuteSql(&sql); err != nil {
		return errors.Wrapf(err, "could not execute contents of sql file %s", file)
	}
	return nil
}

func (pd *PostgresDatabase) Migrate() error {
	log.Trace("repository/postgres/pg_database: Migrate() Entering")
	defer log.Trace("repository/postgres/pg_database: Migrate() Leaving")

	pd.DB.AutoMigrate(types.Host{})
	pd.DB.AutoMigrate(types.Tenant{})
	pd.DB.AutoMigrate(types.HostTenantMapping{}).AddForeignKey("tenant_uuid", "tenants(id)", "RESTRICT", "RESTRICT")
	pd.DB.AutoMigrate(types.TenantPluginCredential{}).AddForeignKey("tenant_uuid", "tenants(id)", "RESTRICT", "RESTRICT")
	return nil
}

func (pd *PostgresDatabase) HostRepository() repository.HostRepository {
	return &PostgresHostRepository{db: pd.DB}
}

func (pd *PostgresDatabase) TenantRepository() repository.TenantRepository {
	return &PostgresTenantRepository{db: pd.DB}
}
func (pd *PostgresDatabase) HostTenantMappingRepository() repository.HostTenantMappingRepository {
	return &PostgresHostTenantMappingRepository{db: pd.DB}
}

func (pd *PostgresDatabase) TenantPluginCredentialRepository() repository.TenantPluginCredentialRepository {
	return &PostgresTenantPluginCredentialRepository{db: pd.DB}
}

func (pd *PostgresDatabase) Close() {
	if pd.DB != nil {
		pd.DB.Close()
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {
	log.Trace("repository/postgres/pg_database: Open() Entering")
	defer log.Trace("repository/postgres/pg_database: Open() Leaving")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 5
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			log.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		log.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		return nil, errors.Wrapf(dbErr, "Failed to connect to db after %d attempts", numAttempts)
	}
	return &PostgresDatabase{DB: db}, nil
}

func VerifyConnection(host string, port int, dbname, user, password, sslMode, sslCert string) error {
	log.Trace("repository/postgres/pg_database: VerifyConnection() Entering")
	defer log.Trace("repository/postgres/pg_database: VerifyConnection() Leaving")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	db, dbErr := gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		host, port, user, dbname, password, sslMode, sslCertParams))

	if dbErr != nil {
		return errors.Wrap(dbErr, "could not connect to database")
	}
	db.Close()
	return nil
}