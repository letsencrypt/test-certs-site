package config

import (
	"encoding/json"
	"time"
)

// Duration adds JSON unmarshalling to time.Duration
type Duration time.Duration

func (d *Duration) UnmarshalJSON(bytes []byte) error {
	var str string
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	dur, err := time.ParseDuration(str)
	if err != nil {
		return err
	}

	*d = Duration(dur)

	return nil
}
