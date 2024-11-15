// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package authorizer

import (
    "log"
    "fmt"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
    "bytes"
    "strings"
    "encoding/json"
    "net/http"
    "io/ioutil"
)

type myClaimMapper struct{}

func NewMyClaimMapper(_ *config.Config) authorization.ClaimMapper {
	return &myClaimMapper{}
}

func checkNamespaceAuthz(token string, namespace string) string {
 	url := "http://temporalauthproxy:3030/auth-proxy"
 	postBody, _ := json.Marshal(map[string]string{
                  "token":  token,
                  "namespace": "default",
               })
    fmt.Println(string(postBody))
        	// We can set the content type here
        	resp, err := http.Post(url, "application/json", bytes.NewReader(postBody))

        	body, err := ioutil.ReadAll(resp.Body)
               if err != nil {
                  log.Fatalln(err)
               }
               sb := string(body)
               fmt.Println("Status:", sb)
 	return sb
 }

func (c myClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := authorization.Claims{}

	if authInfo.TLSConnection != nil {
		// Add claims based on client's TLS certificate
		claims.Subject = authInfo.TLSSubject.CommonName
	}
	if authInfo.AuthToken != "" {
		// Extract claims from the auth token and translate them into Temporal roles for the caller
		// Here we'll simply hardcode some as an example
		log.Println("Token")
		log.Println(authInfo.AuthToken)
        log.Println("auth-Info")
        log.Println(authInfo)
		parts := strings.Split(authInfo.AuthToken, " ")
        if len(parts) != 2 {
        		return nil, fmt.Errorf("unexpected authorization token format")
        }
        authzCheck := checkNamespaceAuthz(parts[1], "default")
        if (authzCheck != "") {
            claims.System = authorization.RoleWriter// cluster-level admin
            claims.Namespaces = make(map[string]authorization.Role)
            namespaces := strings.Split(authzCheck, ",")
            for i := 0; i < len(namespaces); i++ {
                  claims.Namespaces[namespaces[i]] = authorization.RoleWriter
            }

        }else{
          claims.System = authorization.RoleReader// cluster-level admin
        }


	}

	return &claims, nil
}
