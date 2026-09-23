package main

import (
	"testing"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/stretchr/testify/require"
)

type mockAPIHost struct {
	api.Host
	t         *testing.T
	getConfig func() []byte
}

func (h mockAPIHost) GetConfig() []byte {
	return h.getConfig()
}

func (h mockAPIHost) EnableFeatures(features api.Features) api.Features {
	return features
}

func (h mockAPIHost) LogEnabled(api.LogLevel) bool {
	return h.t != nil
}

func (h mockAPIHost) Log(_ api.LogLevel, msg string) {
	h.t.Log(msg)
}

func TestGetDirectivesFromHost(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		_, err := getConfigFromHost(mockAPIHost{t: t, getConfig: func() []byte {
			return nil
		}})
		require.ErrorContains(t, err, "invalid host config")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
			return []byte("abcd")
		}})
		require.ErrorContains(t, err, "invalid host config")
	})

	t.Run("invalid directives value", func(t *testing.T) {
		_, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
			return []byte("{\"directives\": true}")
		}})
		require.ErrorContains(t, err, "invalid host config")
	})

	t.Run("empty directives", func(t *testing.T) {
		_, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
			return []byte("{\"directives\": []}")
		}})
		require.ErrorContains(t, err, "empty directives")
	})

	t.Run("valid directives", func(t *testing.T) {
		cfg, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
			return []byte(`
			{
				"directives": [
					"SecRuleEngine On",
					"SecDebugLog /etc/var/logs/coraza.conf"
				]
			}
			`)
		}})
		require.True(t, cfg.includeCRS)
		require.NoError(t, err)
		require.Equal(t, "SecRuleEngine On\nSecDebugLog /etc/var/logs/coraza.conf", cfg.directives)
	})
}

func TestConfigValidation(t *testing.T) {
	for _, raw := range []string{
		` `, `null`, `[]`, `true`, `"config"`, `{}`,
		`{"directives":["SecRuleEngine On"]`,
		`{"directives":["SecRuleEngine On"]} garbage`,
		`{"directives":["SecRuleEngine On"]} {}`,
		`{"directives":null}`, `{"directives":["", " \t\n"]}`,
		`{"directives":["SecRuleEngine On",1]}`,
		`{"directives":[true]}`, `{"directives":[null]}`,
		`{"directives":[{}]}`, `{"directives":[[]]}`,
		`{"directives":["SecRuleEngine On"],"includeCRS":"true"}`,
		`{"directives":["SecRuleEngine On"],"includeCRS":1}`,
		`{"directives":["SecRuleEngine On"],"includeCRS":null}`,
	} {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			_, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
				calls++
				return []byte(raw)
			}})
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
	for _, includeCRS := range []bool{true, false} {
		t.Run(hostConfig(includeCRS, "SecRuleEngine Off"), func(t *testing.T) {
			calls := 0
			cfg, err := getConfigFromHost(mockAPIHost{getConfig: func() []byte {
				calls++
				return []byte(hostConfig(includeCRS, "SecRuleEngine Off"))
			}})
			require.NoError(t, err)
			require.Equal(t, includeCRS, cfg.includeCRS)
			require.Equal(t, "SecRuleEngine Off", cfg.directives)
			require.Equal(t, 1, calls)
		})
	}
	_, err := initializeWAF(mockAPIHost{getConfig: func() []byte {
		return []byte(`{"directives":["SecRuleEngine Off"],"futureOption":{"enabled":true}}`)
	}})
	require.NoError(t, err)
}

type limitedFeatureHost struct {
	mockAPIHost
	features api.Features
}

func (h limitedFeatureHost) EnableFeatures(api.Features) api.Features { return h.features }

func TestInitializeRequiresBuffering(t *testing.T) {
	for _, features := range []api.Features{0, api.FeatureBufferRequest, api.FeatureBufferResponse} {
		t.Run(features.String(), func(t *testing.T) {
			w, err := initializeWAF(limitedFeatureHost{features: features})
			require.ErrorContains(t, err, "required buffering unavailable")
			require.Nil(t, w)
		})
	}
}

func TestParseSourceAddress(t *testing.T) {
	for _, tc := range []struct {
		input, address string
		port           int
	}{
		{"192.0.2.1:8080", "192.0.2.1", 8080},
		{"192.0.2.1", "192.0.2.1", 0},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"2001:db8::1", "2001:db8::1", 0},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"[fe80::1%eth0]:80", "fe80::1", 80},
		{"192.0.2.1:0", "192.0.2.1", 0},
		{"", "", 0}, {"garbage", "", 0}, {"localhost:80", "", 0},
		{"192.0.2.1:-1", "", 0}, {"192.0.2.1:65536", "", 0},
		{"192.0.2.1:abc", "", 0}, {"[2001:db8::1]:", "", 0},
		{"[192.0.2.1]", "", 0},
	} {
		t.Run(tc.input, func(t *testing.T) {
			address, port := parseSourceAddress(tc.input)
			require.Equal(t, tc.address, address)
			require.Equal(t, tc.port, port)
		})
	}
}

func TestInitializeWAF(t *testing.T) {
	_, err := initializeWAF(mockAPIHost{t: t, getConfig: func() []byte {
		return []byte(`
		{
			"directives": [
				"SecRuleEngine On",
				"SecDebugLog /dev/stdout",
				"SecDebugLogLevel 9",
				"SecRule REQUEST_URI \"@rx .\" \"phase:1,deny,status:403,id:'1234'\""
			]
		}`)
	}})
	require.NoError(t, err)
}
