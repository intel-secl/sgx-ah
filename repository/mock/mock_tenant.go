/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/sgx-attestation-hub/types"
)

type MockTenantRepository struct {
	CreateFunc      func(types.Tenant) (*types.Tenant, error)
	RetrieveFunc    func(types.Tenant) (*types.Tenant, error)
	RetrieveAllFunc func(types.Tenant) (types.Tenants, error)
	UpdateFunc      func(types.Tenant) error
	DeleteFunc      func(types.Tenant) error
}

func (m *MockTenantRepository) Create(t types.Tenant) (*types.Tenant, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(t)
	}
	return nil, nil
}

func (m *MockTenantRepository) Retrieve(t types.Tenant) (*types.Tenant, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(t)
	}
	return nil, nil
}

func (m *MockTenantRepository) RetrieveAll(t types.Tenant) (types.Tenants, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(t)
	}
	return nil, nil
}

func (m *MockTenantRepository) Update(t types.Tenant) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(t)
	}
	return nil
}

func (m *MockTenantRepository) Delete(t types.Tenant) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(t)
	}
	return nil
}
