package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "regexp"
    "time"
)

const (
    baseURL        = "https://xss.report"
    dashboardURL   = baseURL + "/dashboard/%d"
    regexPattern   = `/d/[0-9a-z]{128}`
    deleteParam    = "?del=1"
    cookie         = "xss=eyJ0exxxxxxx"
    userAgent      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    acceptHeader   = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    secFetchSite   = "same-origin"
    secFetchMode   = "navigate"
    secFetchUser   = "?1"
    secFetchDest   = "document"
    requestTimeout = 10 * time.Second
    maxRetries = 3
    retryDelay = 2 * time.Second
)

var client *http.Client
var compiledRegex *regexp.Regexp

func init() {
    // Initializes HTTP clients and regular expressions to prevent repeated creation
    client = &http.Client{
        Timeout: requestTimeout,
    }
    compiledRegex = regexp.MustCompile(regexPattern)
}

// sendRequest Encapsulates the logic for sending HTTP requests, including retry mechanisms
func sendRequest(req *http.Request) (*http.Response, error) {
    var resp *http.Response
    var err error

    for i := 0; i <= maxRetries; i++ {
        resp, err = client.Do(req)
        if err == nil {
            // The request is successful, and a response is returned
            return resp, nil
        }

        // Log an error
        log.Printf("Attempt %d failed: %v, URL: %s", i+1, err, req.URL.String())

        // If the maximum number of retries is reached, an error is returned
        if i == maxRetries {
            break
        }

        // Wait a while and try again
        time.Sleep(retryDelay)
    }
    return nil, fmt.Errorf("request failed after %d retries: %w, URL: %s", maxRetries+1, err, req.URL.String())
}

// buildRequest builds HTTP requests
func buildRequest(method, urlStr string) (*http.Request, error) {
    req, err := http.NewRequest(method, urlStr, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request for URL %s: %w", urlStr, err)
    }

    req.Header.Set("Host", "xss.report")
    req.Header.Set("Cookie", cookie)
    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Accept", acceptHeader)
    req.Header.Set("Sec-Fetch-Site", secFetchSite)
    req.Header.Set("Sec-Fetch-Mode", secFetchMode)
    req.Header.Set("Sec-Fetch-User", secFetchUser)
    req.Header.Set("Sec-Fetch-Dest", secFetchDest)
    return req, nil
}

// extractAndDelete handles a single dashboard URL
func extractAndDelete(dashboardID int) error {
    // Build the dashboard URL
    dashboardURL := fmt.Sprintf(dashboardURL, dashboardID)

    // Build a request to get the content of the dashboard
    req, err := buildRequest("GET", dashboardURL)
    if err != nil {
        return fmt.Errorf("failed to build dashboard request: %w", err)
    }

    // Send the request and get the response
    resp, err := sendRequest(req)
    if err != nil {
        return fmt.Errorf("failed to get dashboard content: %w", err)
    }
    defer func() {
        if closeErr := resp.Body.Close(); closeErr != nil {
            log.Printf("Failed to close response body: %v", closeErr)
        }
    }()

    // Check the HTTP status code
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("HTTP request to %s failed with status code: %d", dashboardURL, resp.StatusCode)
    }

    // Read response content
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read dashboard response body: %w", err)
    }

    // Use regular expressions to find matches
    matches := compiledRegex.FindAllString(string(body), -1)

    // If there is a match, the processing continues
    if len(matches) > 0 {
        for _, match := range matches {
            finalURL := baseURL + match + deleteParam

            // Build delete request
            delReq, err := buildRequest("GET", finalURL)
            if err != nil {
                log.Printf("Failed to create a delete request. Procedure: %v", err)
                continue // Move on to the next match
            }

            // Sending a Delete request
            delResp, err := sendRequest(delReq)
            if err != nil {
                log.Printf("Delete request failed: %v", err)
                continue // Move on to the next match
            }

            defer func() {
                if closeErr := delResp.Body.Close(); closeErr != nil {
                    log.Printf("Failed to close delete response body: %v", closeErr)
                }
            }()

            fmt.Printf("deleting: %s\n", finalURL)
        }
    } else {
        fmt.Printf("No match was found in URL %s.\n", dashboardURL)
    }
    return nil
}

func main() {
    // Go through 1 to 40
    for i := 1; i <= 40; i++ {
        if err := extractAndDelete(i); err != nil {
            log.Printf("Error processing dashboard %d: %v", i, err)
        }
    }

    fmt.Println("Scan completed.")
}
