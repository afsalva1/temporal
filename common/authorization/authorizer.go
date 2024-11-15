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
	"context"
    "log"
    "strings"
	"go.temporal.io/server/common/authorization"
)

type myAuthorizer struct{}

func NewMyAuthorizer() authorization.Authorizer {
	return &myAuthorizer{}
}

var decisionAllow = authorization.Result{Decision: authorization.DecisionAllow}
var decisionDeny = authorization.Result{Decision: authorization.DecisionDeny}

var readOnlyNamespaceAPI = map[string]struct{}{
	"DescribeNamespace":              {},
	"GetWorkflowExecutionHistory":    {},
	"ListOpenWorkflowExecutions":     {},
	"ListClosedWorkflowExecutions":   {},
	"ListWorkflowExecutions":         {},
	"ListArchivedWorkflowExecutions": {},
	"ScanWorkflowExecutions":         {},
	"CountWorkflowExecutions":        {},
	"QueryWorkflow":                  {},
	"DescribeWorkflowExecution":      {},
	"DescribeTaskQueue":              {},
	"ListTaskQueuePartitions":        {},
}

var readOnlyGlobalAPI = map[string]struct{}{
	"ListNamespaces":      {},
	"GetSearchAttributes": {},
	"GetClusterInfo":      {},
}

func IsReadOnlyNamespaceAPI(api string) bool {
	_, found := readOnlyNamespaceAPI[api]
	return found
}

func IsReadOnlyGlobalAPI(api string) bool {
	_, found := readOnlyGlobalAPI[api]
	return found
}

func (a *myAuthorizer) Authorize(_ context.Context, claims *authorization.Claims,
	target *authorization.CallTarget) (authorization.Result, error) {
     log.Println("target.APIName::::", target.APIName)
     log.Println("claims:: ", claims)
     apiFullName := target.APIName
     targetAPIName := apiFullName[strings.LastIndex(apiFullName, "/")+1:]
     log.Println("targetAPIName:: " , targetAPIName)
     isReadOnlyAPI := IsReadOnlyNamespaceAPI(targetAPIName)
     isGlobalReadOnlyAPI := IsReadOnlyGlobalAPI(targetAPIName)
     log.Println("isReadOnlyAPI: ", isReadOnlyAPI)
     log.Println("isGlobalReadOnlyAPI: ", isGlobalReadOnlyAPI)
     //We can restrict even for default - this is for a playground for internal teams - Make it param based.
     //TODO: Make the restriction in prod.
     if target.Namespace == "temporal-system" {
            log.Println("Skipping authz - temporal-system namespace")
     		return decisionAllow, nil
     }


     if claims == nil {
            log.Println("Skipping authz - claims nil")
     		return decisionAllow, nil
     }


     if ( isReadOnlyAPI || isGlobalReadOnlyAPI ) {
            log.Println("Skipping authz - read API ")
     		return decisionAllow, nil
     }else {
          log.Println("Authz - checking.. ")
          log.Println(claims.System)
          if claims.System & (authorization.RoleAdmin ) != 0 {
          		return decisionAllow, nil
          }
          if claims.Namespaces[target.Namespace] & authorization.RoleWriter != 0 {
                     log.Println("Authz allowed - namespace : " , target.Namespace)
          			return decisionAllow, nil
          } else {
                    log.Println("Authz denied - namespace :" , target.Namespace)
          			return decisionDeny, nil
          }
     }

	// Allow all operations within "temporal-system" namespace
	// DON'T DO THIS IN A PRODUCTION ENVIRONMENT
	// IN PRODUCTION, only allow calls from properly authenticated and authorized callers
	// We are taking a shortcut in the sample because we don't have TLS or a auth token


	// Allow all other requests
	return decisionAllow, nil
}
