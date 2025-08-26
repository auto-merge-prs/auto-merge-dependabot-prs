// Copyright (c) 2025 Martin Nordholts
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v66/github"
	"github.com/shurcooL/githubv4"
)

type Sender int

const (
	SenderGitHub Sender = iota
	SenderUnknown
)

type Outcome string

const (
	EnabledAutoMerge            Outcome = "EnabledAutoMerge"
	NotOpenedPr                 Outcome = "NotOpenedPr"
	NotOpenedByDependabotBut    Outcome = "NotOpenedByDependabotBut"
	NotSentByGitHub             Outcome = "NotSentByGitHub"
	MissingEnvVar               Outcome = "MissingEnvVar"
	MissingHeader               Outcome = "MissingHeader"
	MissingSecret               Outcome = "MissingSecret"
	MissingSecretJson           Outcome = "MissingSecretJson"
	MissingInstallationId       Outcome = "MissingInstallationId"
	GraphQlError                Outcome = "GraphQlError"
	InvalidBody                 Outcome = "InvalidBody"
)

type outcomePayload struct {
	Outcome Outcome      `json:"outcome"`
	// Only used for NotOpenedByDependabotBut and some errors; fields are optional.
	Name    *string      `json:"name,omitempty"`
	ID      *int64       `json:"id,omitempty"`
	Detail  string       `json:"detail,omitempty"`
}

type srvError struct {
	client bool
	out    outcomePayload
}

func clientErr(o outcomePayload) *srvError { return &srvError{client: true, out: o} }
func serverErr(o outcomePayload) *srvError { return &srvError{client: false, out: o} }

func main() {
	lambda.Start(handleEvent)
}

func handleEvent(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	status, out := process(ctx, req)
	body, _ := json.Marshal(out)
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}, nil
}

func process(ctx context.Context, req events.APIGatewayProxyRequest) (int, outcomePayload) {
	out, err := handlePossibleWebhookEvent(ctx, req)
	if err == nil {
		// Non-error outcomes return 200 only for EnabledAutoMerge; otherwise 412.
		if out.Outcome == EnabledAutoMerge {
			return http.StatusOK, out
		}
		return http.StatusPreconditionFailed, out
	}
	if err.client {
		return http.StatusBadRequest, err.out
	}
	return http.StatusInternalServerError, err.out
}

func handlePossibleWebhookEvent(ctx context.Context, req events.APIGatewayProxyRequest) (outcomePayload, *srvError) {
	// Body (may be base64 from API Gateway)
	var bodyBytes []byte
	if req.IsBase64Encoded {
		b, decErr := base64.StdEncoding.DecodeString(req.Body)
		if decErr != nil {
			return outcomePayload{Outcome: InvalidBody}, clientErr(outcomePayload{Outcome: InvalidBody})
		}
		bodyBytes = b
	} else {
		bodyBytes = []byte(req.Body)
	}

	// Ensure this an Opened event of a PR.
	event := header(req, "X-GitHub-Event")
	if event == "" {
		return outcomePayload{Outcome: MissingHeader, Detail: "X-GitHub-Event"}, serverErr(outcomePayload{Outcome: MissingHeader, Detail: "X-GitHub-Event"})
	}
	// Parse as a generic webhook to get fields we need.
	var any map[string]any
	if err := json.Unmarshal(bodyBytes, &any); err != nil {
		return outcomePayload{Outcome: InvalidBody}, clientErr(outcomePayload{Outcome: InvalidBody})
	}

	// Only proceed for pull_request events with action == "opened"
	if event != "pull_request" || getString(any, "action") != "opened" {
		return outcomePayload{Outcome: NotOpenedPr}, nil
	}

	// PR node_id
	pr := getMap(any, "pull_request")
	prNodeID := getString(pr, "node_id")
	if prNodeID == "" {
		// Shouldn't happen for opened PRs, but treat as client error
		return outcomePayload{Outcome: InvalidBody, Detail: "missing pull_request.node_id"}, clientErr(outcomePayload{Outcome: InvalidBody, Detail: "missing pull_request.node_id"})
	}

	// Sender info
	sender := getMap(any, "sender")
	senderLogin := getString(sender, "login")
	var senderIDPtr *int64
	if id, ok := getInt64(sender, "id"); ok {
		senderIDPtr = &id
	}

	isDep, depErr := isDependabot(senderLogin, senderIDPtr)
	if depErr != nil {
		return outcomePayload{Outcome: MissingEnvVar, Detail: depErr.Error()}, serverErr(outcomePayload{Outcome: MissingEnvVar, Detail: depErr.Error()})
	}
	if !isDep {
		return outcomePayload{
			Outcome: NotOpenedByDependabotBut,
			Name:    strPtr(senderLogin),
			ID:      senderIDPtr,
		}, nil
	}

	// Ensure the event was actually sent by GitHub (signature)
	senderType, sigErr := eventSender(req, bodyBytes)
	if sigErr != nil {
		return outcomePayload{Outcome: MissingSecret, Detail: sigErr.Error()}, serverErr(outcomePayload{Outcome: MissingSecret, Detail: sigErr.Error()})
	}
	if senderType != SenderGitHub {
		return outcomePayload{Outcome: NotSentByGitHub}, nil
	}

	// Installation ID
	installation := getMap(any, "installation")
	instIDf, ok := installation["id"].(float64)
	if !ok {
		return outcomePayload{Outcome: MissingInstallationId}, serverErr(outcomePayload{Outcome: MissingInstallationId})
	}
	installationID := int64(instIDf)

	// GitHub App authentication (installation client) using private key
	appIDStr, err := requiredEnv("AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID")
	if err != nil {
		return outcomePayload{Outcome: MissingEnvVar, Detail: "AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID"}, serverErr(outcomePayload{Outcome: MissingEnvVar, Detail: "AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID"})
	}
	privateKey, err := getSecret("AUTO_MERGE_DEPENDABOT_PRS_PRIVATE_KEY_SECRET_ID")
	if err != nil {
		return outcomePayload{Outcome: MissingSecret, Detail: "AUTO_MERGE_DEPENDABOT_PRS_PRIVATE_KEY_SECRET_ID"}, serverErr(outcomePayload{Outcome: MissingSecret, Detail: "AUTO_MERGE_DEPENDABOT_PRS_PRIVATE_KEY_SECRET_ID"})
	}
	var appID int64
	_, scanErr := fmt.Sscanf(appIDStr, "%d", &appID)
	if scanErr != nil {
		return outcomePayload{Outcome: MissingEnvVar, Detail: "AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID parse error"}, serverErr(outcomePayload{Outcome: MissingEnvVar, Detail: "AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID parse error"})
	}

	// Build transports: app -> installation
	appTr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, []byte(privateKey))
	if err != nil {
		return outcomePayload{Outcome: GraphQlError, Detail: "apps transport: " + err.Error()}, serverErr(outcomePayload{Outcome: GraphQlError, Detail: "apps transport: " + err.Error()})
	}
	instTr := ghinstallation.NewFromAppsTransport(appTr, installationID)
	httpClient := &http.Client{Transport: instTr, Timeout: 30 * time.Second}

	// githubv4 client shares http transport and auth
	ghv4 := githubv4.NewClient(httpClient)

	// 1) enable auto-merge
	if err := enablePullRequestAutoMerge(ctx, ghv4, prNodeID); err != nil {
		return outcomePayload{Outcome: GraphQlError, Detail: err.Error()}, serverErr(outcomePayload{Outcome: GraphQlError, Detail: err.Error()})
	}

	// 2) add comment announcing it
	if err := addPRComment(ctx, ghv4, prNodeID, "If CI passes, this dependabot PR will be [auto-merged](https://github.com/apps/auto-merge-dependabot-prs) 🚀"); err != nil {
		return outcomePayload{Outcome: GraphQlError, Detail: err.Error()}, serverErr(outcomePayload{Outcome: GraphQlError, Detail: err.Error()})
	}

	return outcomePayload{Outcome: EnabledAutoMerge}, nil
}

func enablePullRequestAutoMerge(ctx context.Context, ghv4 *githubv4.Client, prNodeID string) error {
	var m struct {
		EnablePullRequestAutoMerge struct {
			PullRequest struct {
				ID githubv4.ID
			} `graphql:"pullRequest"`
		} `graphql:"enablePullRequestAutoMerge(input: $input)"`
	}
	input := map[string]any{
		"input": githubv4.EnablePullRequestAutoMergeInput{
			PullRequestID: githubv4.ID(prNodeID),
		},
	}
	if err := ghv4.Mutate(ctx, &m, input, nil); err != nil {
		return fmt.Errorf("enable auto-merge: %w", err)
	}
	if fmt.Sprint(m.EnablePullRequestAutoMerge.PullRequest.ID) != prNodeID {
		return fmt.Errorf("PR id mismatch: `%v` != `%s`", m.EnablePullRequestAutoMerge.PullRequest.ID, prNodeID)
	}
	return nil
}

func addPRComment(ctx context.Context, ghv4 *githubv4.Client, subjectID, body string) error {
	var m struct {
		AddComment struct {
			Subject struct {
				ID githubv4.ID
			}
		} `graphql:"addComment(input: $input)"`
	}
	input := map[string]any{
		"input": githubv4.AddCommentInput{
			SubjectID: githubv4.ID(subjectID),
			Body:      githubv4.String(body),
		},
	}
	if err := ghv4.Mutate(ctx, &m, input, nil); err != nil {
		return fmt.Errorf("add comment: %w", err)
	}
	if fmt.Sprint(m.AddComment.Subject.ID) != subjectID {
		return fmt.Errorf("PR id mismatch: `%v` != `%s`", m.AddComment.Subject.ID, subjectID)
	}
	return nil
}

func isDependabot(senderLogin string, senderID *int64) (bool, error) {
	want, err := requiredEnv("AUTO_MERGE_DEPENDABOT_PRS_DEPENDABOT_USER_NAME_AND_ID")
	if err != nil {
		return false, err
	}
	var idPart string
	if senderID != nil {
		idPart = fmt.Sprintf("%d", *senderID)
	}
	got := fmt.Sprintf("%s,%s", senderLogin, idPart)
	return got == want, nil
}

func eventSender(req events.APIGatewayProxyRequest, body []byte) (Sender, error) {
	sig := header(req, "X-Hub-Signature-256")
	if sig == "" {
		return SenderUnknown, fmt.Errorf("missing X-Hub-Signature-256")
	}
	secret, err := getSecret("AUTO_MERGE_DEPENDABOT_PRS_WEBHOOK_SECRET_ID")
	if err != nil {
		return SenderUnknown, err
	}
	if verifySHA256(sig, secret, body) {
		return SenderGitHub, nil
	}
	return SenderUnknown, nil
}

func verifySHA256(signature, secret string, body []byte) bool {
	// signature is "sha256=<hex>"
	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sum := mac.Sum(nil)
	expected := hex.EncodeToString(sum)
	return hmac.Equal([]byte(signature[len(prefix):]), []byte(expected))
}

func header(req events.APIGatewayProxyRequest, name string) string {
	// API Gateway headers are case-insensitive; AWS gives a normalized map.
	if v, ok := req.Headers[name]; ok {
		return v
	}
	// Fallback: try lowercase key
	return req.Headers[strings.ToLower(name)]
}

func requiredEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s not set", name)
	}
	return v, nil
}

func getSecret(secretIDEnv string) (string, error) {
	token, err := requiredEnv("AWS_SESSION_TOKEN")
	if err != nil {
		return "", err
	}
	secretID, err := requiredEnv(secretIDEnv)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("http://localhost:2773/secretsmanager/get?secretId=%s", secretID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Aws-Parameters-Secrets-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request secret: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("request secret: status %d: %s", resp.StatusCode, string(b))
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}
	if s, ok := v["SecretString"].(string); ok && s != "" {
		return s, nil
	}
	return "", errors.New("MissingSecretJson")
}

// ---- tiny JSON helpers ----

func getMap(m map[string]any, key string) map[string]any {
	if mv, ok := m[key].(map[string]any); ok {
		return mv
	}
	return map[string]any{}
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt64(m map[string]any, key string) (int64, bool) {
	if f, ok := m[key].(float64); ok {
		return int64(f), true
	}
	return 0, false
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// (Optional) If you also want a REST client handy for anything else:
func restClient(httpClient *http.Client) *github.Client {
	return github.NewClient(httpClient)
}
