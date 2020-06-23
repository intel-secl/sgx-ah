package attestationServicePollerJob

import (
	"github.com/pkg/errors"
	clog "intel/isecl/lib/common/v2/log"
	"intel/isecl/shub/constants"
	"intel/isecl/shub/repository"
	"intel/isecl/shub/resource"
	"io/ioutil"
	"time"
)

var log = clog.GetDefaultLogger()

func Execute(shubDB repository.SHUBDatabase) error {
	log.Trace("resource/attestationServicePollerJob/shub_poller: Execute() Entering")
	defer log.Trace("resource/attestationServicePollerJob/shub_poller: Execute() Leaving")

	lastRunDateTimeFileName := constants.ConfigDir + constants.LastRunTimeStampFile
	out, fileExistsErr := resource.FileExists(lastRunDateTimeFileName)
	log.Info("resource/attestationServicePollerJob/shub_poller: Execute() File to save timestamp: ", lastRunDateTimeFileName)
	currentTime := time.Now()
	formattedTime := currentTime.Format(time.UnixDate)

	if out == false {
		log.Debug("resource/attestationServicePollerJob/shub_poller: Execute() Error: ", fileExistsErr)
		err := resource.FetchAllHostsFromHVS(shubDB)
		log.Debug("resource/attestationServicePollerJob/shub_poller: Execute() Error: ", err)
		if err != nil {
			return errors.Wrap(err, "resource/attestationServicePollerJob/shub_poller: Execute() Error in fetching hosts and host data for the first time")
		}
		err = resource.WriteDataIn(lastRunDateTimeFileName, formattedTime)
		if err != nil {
			return errors.Wrap(err, "resource/attestationServicePollerJob/shub_poller: Execute() Error in writing timestamp to the file for the first time")
		}
	} else {
		currentTime := time.Now()
		log.Info("resource/attestationServicePollerJob/shub_poller: Execute() current time is: --------------------------", time.Now())

		lastDateTimeFromLastRunFile, err := ioutil.ReadFile(lastRunDateTimeFileName)
		if err != nil {
			return errors.Wrapf(err, "resource/attestationServicePollerJob/shub_poller: Execute() could not read file - %s", lastRunDateTimeFileName)
		}

		t, err := time.Parse("Mon Jan 2 15:04:05 MST 2006", string(lastDateTimeFromLastRunFile))
		log.Info("resource/attestationServicePollerJob/shub_poller: Execute() time read from file is: ------------------------------------", t)
		if err != nil {
			return errors.Wrapf(err,"resource/attestationServicePollerJob/shub_poller: Execute() error in parsing timestamp present in file %s", lastRunDateTimeFileName)
		}

		timeDifferenceInMinutes := currentTime.Sub(t)
		log.Info("resource/attestationServicePollerJob/shub_poller: Execute() difference in current time and time read from file is: ---------------------------", timeDifferenceInMinutes)

		// Since int returns time in nanoseconds, need to divide it by 6e+10 to convert it into minutes
		timeDifferenceInt := int(timeDifferenceInMinutes)/(6e+10)
		err = resource.FetchHostRegisteredInLastFewMinutes(shubDB, timeDifferenceInt)
		log.Debug("resource/attestationServicePollerJob/shub_poller: Execute() Error: ", err)
		if err != nil {
			return errors.Wrap(err, "resource/attestationServicePollerJob/shub_poller: Execute() Error in fetching hosts and corresponding host data updated in last few minutes")
		}
		err = resource.WriteDataIn(lastRunDateTimeFileName, formattedTime)
		if err != nil {
			return errors.Wrap(err, "resource/attestationServicePollerJob/shub_poller: Execute() Error in updating timestamp of the file")
		}
	}
	return nil

}
