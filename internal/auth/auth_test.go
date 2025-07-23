package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "valid API key",
			authHeader:     "ApiKey valid-api-key-123",
			expectedAPIKey: "valid-api-key-123",
			expectedError:  nil,
		},
		{
			name:           "malformed header - wrong authorization type",
			authHeader:     "Bearer token-123",
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "malformed header - no space after ApiKey",
			authHeader:     "ApiKey",
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "missing authorization header",
			authHeader:     "", // This will be handled by not setting the header
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}

			// Handle the special case where we don't set the header at all
			if tt.name == "missing authorization header" {
				// Don't set any header
			} else {
				headers.Set("Authorization", tt.authHeader)
			}

			apiKey, err := GetAPIKey(headers)

			// Check API key
			if apiKey != tt.expectedAPIKey {
				t.Errorf("GetAPIKey() apiKey = %v, want %v", apiKey, tt.expectedAPIKey)
			}

			// Check error
			if tt.expectedError == nil {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
				}
			}
		})
	}
}
