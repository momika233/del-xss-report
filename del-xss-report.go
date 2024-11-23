package main

import (
    "fmt"
    "net/http"
    "regexp"
    "io/ioutil"
    "log"
)

func main() {
    // Creating an HTTP client
    client := &http.Client{}

    // Go through 1 to 100
    for i := 1; i <= 40; i++ {
        // Dynamically generate URL
        url := fmt.Sprintf("https://xss.report/dashboard/%d", i)

        // Construct request
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            log.Printf("Create request failed: %v", err)
            continue
        }

        // Set request header
        req.Header.Set("Host", "xss.report")
        req.Header.Set("Cookie", "xss=eyJ0exxxxxxxxxxxxxxxxxx")
        req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
        req.Header.Set("Sec-Fetch-Site", "same-origin")
        req.Header.Set("Sec-Fetch-Mode", "navigate")
        req.Header.Set("Sec-Fetch-User", "?1")
        req.Header.Set("Sec-Fetch-Dest", "document")

        // Send request
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Request failed: %v", err)
            continue
        }
        defer resp.Body.Close()

        // Read the response content and convert it to a string
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Printf("Failed to read the response content: %v", err)
            continue
        }

        // Use regular expression matching `/d/[0-9a-z]{128}`
        re := regexp.MustCompile(`/d/[0-9a-z]{128}`)
        matches := re.FindAllString(string(body), -1)

        // If there is a match, continue processing
        if len(matches) > 0 {
            for _, match := range matches {
                finalURL := "https://xss.report" + match + "?del=1"

                fmt.Printf("deleting: %s\n", finalURL)


                delReq, err := http.NewRequest("GET", finalURL, nil)
                if err != nil {
                    log.Printf("Failed to create a delete request. Procedure: %v", err)
                    continue
                }

                delReq.Header.Set("Host", "xss.report")
                delReq.Header.Set("Cookie", "xss=eyJ0exxxxxxxxxxxxxxxxxx")
                delReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
                delReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
                delReq.Header.Set("Sec-Fetch-Site", "same-origin")
                delReq.Header.Set("Sec-Fetch-Mode", "navigate")
                delReq.Header.Set("Sec-Fetch-User", "?1")
                delReq.Header.Set("Sec-Fetch-Dest", "document")


                delResp, err := client.Do(delReq)
                if err != nil {
                    log.Printf("Delete request failed: %v", err)
                    continue
                }
                defer delResp.Body.Close()

            }
        } else {
            fmt.Printf("No match was found in URL %s.\n", url)
        }
    }
}
