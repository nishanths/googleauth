# googleauth

Example code for authenticating users using Google via OAuth2 and setting
cookies in a web application.

## Resources

- https://godoc.org/golang.org/x/oauth2/google
- https://developers.google.com/identity/protocols/oauth2/openid-connect
- How HTTP Cookies Work: https://thoughtbot.com/blog/lucky-cookies
- https://github.com/gorilla/securecookie

## Google Client ID and Client Secret

Obtain them here for your Google Cloud project: https://console.cloud.google.com/apis/credentials

## Hash key and Block key for cookies

Generate them using `go run genkey/genkey.go`. See the comments in `genkey.go`
and the securecookie package's godoc for more info.
