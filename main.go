/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/shub/constants"
	_ "intel/isecl/shub/swagger/docs"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.LogFile, 0664)

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.HTTPLogFile, 0664)

	secLogFile, err = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.SecurityLogFile, 0664)

	shubUser, err := user.Lookup(constants.SHUBUserName)
	if err != nil {
		log.Errorf("Could not find user '%s'", constants.SHUBUserName)
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(shubUser.Uid)
	if err != nil {
		log.Errorf("Could not parse shub user uid '%s'", shubUser.Uid)
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(shubUser.Gid)
	if err != nil {
		log.Errorf("Could not parse shub user gid '%s'", shubUser.Gid)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.HTTPLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.SecurityLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.SecurityLogFile)
	}

	err = os.Chown(constants.LogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
		return nil, nil, nil, err
	}

	return
}

func main() {
	l, h, s, err := openLogFiles()
	var app *App
	if err != nil {
		app = &App{
			LogWriter: os.Stdout,
		}
	} else {
		defer l.Close()
		defer h.Close()
		defer s.Close()
		app = &App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}
	err = app.Run(os.Args)
	if err != nil {
		log.Error("Application returned with error: ", err)
		os.Exit(1)
	}
}
