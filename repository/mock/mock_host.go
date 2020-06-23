/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/shub/types"
)

type MockHostRepository struct {
	CreateFunc      func(types.Host) (*types.Host, error)
	RetrieveFunc    func(types.Host) (*types.Host, error)
	RetrieveAllFunc func(types.Host) (types.Hosts, error)
	UpdateFunc      func(types.Host) error
	DeleteFunc      func(types.Host) error
}

func (m *MockHostRepository) Create(h types.Host) (*types.Host, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(h)
	}
	return nil, nil
}

func (m *MockHostRepository) Retrieve(h types.Host) (*types.Host, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(h)
	}
	return nil, nil
}

func (m *MockHostRepository) RetrieveAll(h types.Host) (types.Hosts, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(h)
	}
	return nil, nil
}

func (m *MockHostRepository) Update(h types.Host) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(h)
	}
	return nil
}

func (m *MockHostRepository) Delete(h types.Host) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(h)
	}
	return nil
}

