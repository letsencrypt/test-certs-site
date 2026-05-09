package config

import (
	"encoding/json"
	"time"
)

// Duration adds JSON unmarshalling to time.Duration
type Duration time.Duration

// UnmarshalJSON as a string, parsing with time.ParseDuration
func (d *Duration) UnmarshalJSON(bytes []byte) error {
	var str string
	err := json.Unmarshal(bytes, &str)
	if err != nil {
		return err
	}
	dur, err := time.ParseDuration(str)
	if err != nil {
		return err
	}

	*d = Duration(dur)

	return nil
}

// MarshalJSON as a string, in time.Duration's String form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}
