package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedAPIKey string
	}{
		{
			name:           "Valid ApiKey header",
			authHeader:     "ApiKey abc123xyz",
			expectedAPIKey: "abc123xyz",
		},
		{
			name:           "Valid ApiKey with complex key",
			authHeader:     "ApiKey sk_test_51H8F9xKj2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8",
			expectedAPIKey: "sk_test_51H8F9xKj2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8",
		},
		{
			name:           "Valid ApiKey with UUID",
			authHeader:     "ApiKey 550e8400-e29b-41d4-a716-446655440000",
			expectedAPIKey: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:           "Valid ApiKey with extra spaces after (only first split matters)",
			authHeader:     "ApiKey mykey extra stuff",
			expectedAPIKey: "mykey",
		},
		{
			name:           "ApiKey with trailing space - returns empty string as key",
			authHeader:     "ApiKey ",
			expectedAPIKey: "",
		},
		{
			name:           "Multiple spaces between ApiKey and key - returns empty string",
			authHeader:     "ApiKey    abc123xyz",
			expectedAPIKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)

			// Act
			apiKey, err := GetAPIKey(headers)

			// Assert
			if err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
			if apiKey != tt.expectedAPIKey {
				t.Errorf("Expected API key %q, got %q", tt.expectedAPIKey, apiKey)
			}
		})
	}
}

func TestGetAPIKey_MissingAuthHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
	}{
		{
			name:    "No Authorization header at all",
			headers: http.Header{},
		},
		{
			name: "Has other headers but not Authorization",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
				"User-Agent":   []string{"test-agent"},
			},
		},
		{
			name: "Empty Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			apiKey, err := GetAPIKey(tt.headers)

			// Assert
			if !errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Errorf("Expected ErrNoAuthHeaderIncluded, got: %v", err)
			}
			if apiKey != "" {
				t.Errorf("Expected empty API key, got: %q", apiKey)
			}
		})
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		reason     string
	}{
		{
			name:       "Only ApiKey without space or key",
			authHeader: "ApiKey",
			reason:     "no space or key part",
		},
		{
			name:       "Wrong prefix - Bearer instead of ApiKey",
			authHeader: "Bearer abc123xyz",
			reason:     "wrong auth scheme",
		},
		{
			name:       "Wrong prefix - Basic instead of ApiKey",
			authHeader: "Basic abc123xyz",
			reason:     "wrong auth scheme",
		},
		{
			name:       "Lowercase apikey",
			authHeader: "apikey abc123xyz",
			reason:     "incorrect case",
		},
		{
			name:       "Wrong case - APIKEY",
			authHeader: "APIKEY abc123xyz",
			reason:     "incorrect case",
		},
		{
			name:       "No space between ApiKey and key",
			authHeader: "ApiKeyabc123xyz",
			reason:     "no space separator",
		},
		{
			name:       "Only the key without prefix",
			authHeader: "abc123xyz",
			reason:     "missing ApiKey prefix",
		},
		{
			name:       "Empty string with just spaces",
			authHeader: "   ",
			reason:     "only whitespace",
		},
		{
			name:       "Tab character instead of space",
			authHeader: "ApiKey\tabc123xyz",
			reason:     "tab instead of space",
		},
		{
			name:       "Newline in header",
			authHeader: "ApiKey\nabc123xyz",
			reason:     "newline character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)

			// Act
			apiKey, err := GetAPIKey(headers)

			// Assert
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.reason)
			}
			if err != nil && err.Error() != "malformed authorization header" {
				t.Errorf("Expected 'malformed authorization header' error, got: %v", err)
			}
			if apiKey != "" {
				t.Errorf("Expected empty API key for malformed header, got: %q", apiKey)
			}
		})
	}
}

func TestGetAPIKey_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedAPIKey string
		expectError    bool
		errorType      error
	}{
		{
			name:           "Very long API key",
			authHeader:     "ApiKey " + string(make([]byte, 1000)),
			expectedAPIKey: string(make([]byte, 1000)),
			expectError:    false,
		},
		{
			name:           "API key with special characters",
			authHeader:     "ApiKey !@#$%^&*()_+-=[]{}|;:,.<>?",
			expectedAPIKey: "!@#$%^&*()_+-=[]{}|;:,.<>?",
			expectError:    false,
		},
		{
			name:           "API key with unicode characters",
			authHeader:     "ApiKey 你好世界🔑",
			expectedAPIKey: "你好世界🔑",
			expectError:    false,
		},
		{
			name:        "Just a space",
			authHeader:  " ",
			expectError: true,
			errorType:   errors.New("malformed authorization header"),
		},
		{
			name:           "ApiKey with empty string as key (space at end)",
			authHeader:     "ApiKey  ",
			expectedAPIKey: "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)

			// Act
			apiKey, err := GetAPIKey(headers)

			// Assert
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if apiKey != tt.expectedAPIKey {
					t.Errorf("Expected API key %q, got %q", tt.expectedAPIKey, apiKey)
				}
			}
		})
	}
}

func TestGetAPIKey_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectError bool
	}{
		{
			name:        "Correct case - ApiKey",
			authHeader:  "ApiKey test123",
			expectError: false,
		},
		{
			name:        "All lowercase - apikey",
			authHeader:  "apikey test123",
			expectError: true,
		},
		{
			name:        "All uppercase - APIKEY",
			authHeader:  "APIKEY test123",
			expectError: true,
		},
		{
			name:        "Mixed case - APIKey",
			authHeader:  "APIKey test123",
			expectError: true,
		},
		{
			name:        "Mixed case - Apikey",
			authHeader:  "Apikey test123",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)

			// Act
			_, err := GetAPIKey(headers)

			// Assert
			if tt.expectError && err == nil {
				t.Errorf("Expected error for case sensitivity test, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for valid case, got: %v", err)
			}
		})
	}
}

func TestGetAPIKey_HeaderManipulation(t *testing.T) {
	t.Run("Multiple Authorization headers - http.Header uses first", func(t *testing.T) {
		// Arrange
		headers := http.Header{}
		// http.Header.Get() returns the first value
		headers["Authorization"] = []string{"ApiKey first123", "ApiKey second456"}

		// Act
		apiKey, err := GetAPIKey(headers)

		// Assert
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if apiKey != "first123" {
			t.Errorf("Expected 'first123', got: %q", apiKey)
		}
	})

	t.Run("Header key case insensitivity", func(t *testing.T) {
		// Arrange
		headers := http.Header{}
		// http.Header.Set is case-insensitive for header names
		headers.Set("authorization", "ApiKey test123")

		// Act
		apiKey, err := GetAPIKey(headers)

		// Assert
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if apiKey != "test123" {
			t.Errorf("Expected 'test123', got: %q", apiKey)
		}
	})

	t.Run("Header with leading/trailing spaces (Set does NOT trim)", func(t *testing.T) {
		// Arrange
		headers := http.Header{}
		headers.Set("Authorization", "  ApiKey test123  ")

		// Act
		_, err := GetAPIKey(headers)

		// Assert
		// http.Header.Set does NOT trim spaces from the value
		// Leading spaces cause the split to fail because first element is not "ApiKey"
		if err == nil {
			t.Errorf("Expected error due to leading spaces, got nil")
		}
		if err != nil && err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got: %v", err)
		}
	})
}
