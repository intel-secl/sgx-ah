/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"strings"
)

func Intersection(section1, section2 []string) (intersection []string) {
	str1 := strings.Join(filter(section1), " ")
	for _, s := range filter(section2) {
		if strings.Contains(str1, s) {
			intersection = append(intersection, s)
		}
	}
	return
}

// Set Difference: A - B
func Difference(a, b []string) (diff []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return diff
}

func filter(src []string) (res []string) {
	for _, s := range src {
		newStr := strings.Join(res, " ")
		if !strings.Contains(newStr, s) {
			res = append(res, s)
		}
	}
	return
}
