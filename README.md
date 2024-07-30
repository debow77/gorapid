# gorapid

RapidClient
===========

A Go client for interacting with the RAPID API.

Installation
------------

To install the RapidClient package, run the following command:

```bash
go get github.cerner.com/OHAIFedAutoSre/gorapid
```

Usage
-----

### Creating a RapidClient instance

To create a new RapidClient instance, you need to provide the base URL, key, and secret for the RAPID API. You can do this by setting the `RAPID_BASE_URL`, `RAPID_KEY`, and `RAPID_SECRET` environment variables.

```go
import "github.cerner.com/OHAIFedAutoSre/gorapid"

func main() {
    client, err := rapid.NewRapidClient()
    if err != nil {
        log.Fatal(err)
    }
    // Use the client to make API requests, see below examples for the Request arguments
    resp, err := rapidClient.Get("your-path", url.Values{"some attribute": {"some value"}})

}
```

Making API requests
-----

The RapidClient provides several methods for making API requests:
- Get(urlPath string, params url.Values) (*Response, error): Performs an HTTP GET request to the specified API endpoint.
- Post(urlPath string, body JSONBody) (*Response, error): Performs an HTTP POST request to the specified API endpoint.
- Put(urlPath string, body JSONBody) (*Response, error): Performs an HTTP PUT request to the specified API endpoint.
- Delete(urlPath string) (*Response, error): Performs an HTTP DELETE request to the specified API endpoint.

Token management
-----

The RapidClient handles token generation and refresh automatically. You can also manually generate a new token using the GenerateToken() method.

Contributing
-----
Contributions are welcome! Please open a pull request or issue on GitHub to contribute to the RapidClient package.

Acknowledgments
-----
The RapidClient package was inspired by the https://github.cerner.com/CWxAutomation/php_rapid.