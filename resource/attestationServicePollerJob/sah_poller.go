package attestationServicePollerJob

import (
	"github.com/pkg/errors"
	clog "intel/isecl/lib/common/v2/log"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/resource"
	"io/ioutil"
	"time"
)

var log = clog.GetDefaultLogger()

func Execute(sahDB repository.SAHDatabase) error {
	log.Trace("resource/attestationServicePollerJob/sah_poller: Execute() Entering")
	defer log.Trace("resource/attestationServicePollerJob/sah_poller: Execute() Leaving")

	lastRunDateTimeFileName := constants.ConfigDir + constants.LastRunTimeStampFile
	out, fileExistsErr := resource.FileExists(lastRunDateTimeFileName)
	log.Info("File to save timestamp: ", lastRunDateTimeFileName)
	currentTime := time.Now()
	formattedTime := currentTime.Format(time.UnixDate)

	if out == false {
		log.Debug("attestationServicePollerJob.Execute(): Error: ", fileExistsErr)
		err := resource.FetchAllHostsFromHVS(sahDB)
		log.Debug("attestationServicePollerJob.Execute(): Error: ", err)
		if err != nil {
			return errors.Wrap(err, "Error in fetching hosts and host data for the first time")
		}
		err = resource.WriteDataIn(lastRunDateTimeFileName, formattedTime)
		if err != nil {
			return errors.Wrap(err, "Error in writing timestamp to the file for the first time")
		}
	} else {
		currentTime := time.Now()
		log.Info("current time is: --------------------------", time.Now())

		lastDateTimeFromLastRunFile, err := ioutil.ReadFile(lastRunDateTimeFileName)
		if err != nil {
			return errors.Wrapf(err, "could not read file - %s", lastRunDateTimeFileName)
		}

		t, err := time.Parse("Mon Jan 2 15:04:05 MST 2006", string(lastDateTimeFromLastRunFile))
		log.Info("time read from file is: ------------------------------------", t)
		if err != nil {
			return errors.Wrapf(err,"error in parsing timestamp present in file %s", lastRunDateTimeFileName)
		}

		timeDifferenceInMinutes := currentTime.Sub(t)
		log.Info("difference in current time and time read from file is: ---------------------------", timeDifferenceInMinutes)

		// Since int returns time in nanoseconds, need to divide it by 6e+10 to convert it into minutes
		timeDifferenceInt := int(timeDifferenceInMinutes)/(6e+10)
		err = resource.FetchHostRegisteredInLastFewMinutes(sahDB, timeDifferenceInt)
		if err != nil {
			log.Info("attestationServicePollerJob.Execute(): ", err)
			return err
		}
		err = resource.WriteDataIn(lastRunDateTimeFileName, formattedTime)
		if err != nil {
			return errors.Wrap(err, "Error in updating timestamp of the file")
		}
	}
	return nil

}
