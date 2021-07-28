package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type KeyCloakClient struct {
	BaseURL     string
	Username    string
	Password    string
	AccessToken string
	Realm       string
	TokenTime   int
	Ctx         context.Context
}

func NewKeyCloakClient(BaseUrl string, Username string, Password string, BaseCtx context.Context, Realm string) (*KeyCloakClient, error) {
	client := KeyCloakClient{
		BaseURL:  BaseUrl,
		Username: Username,
		Password: Password,
		Ctx:      BaseCtx,
		Realm:    Realm,
	}

	return &client, nil
}

func (k *KeyCloakClient) getToken() error {
	if k.AccessToken != "" || k.TokenTime == 0 || k.TokenTime > int(time.Now().Unix()) {
		accessString, err := k.getGenericToken(k.Realm, k.Username, k.Password)
		if err != nil {
			return err
		}
		k.AccessToken = accessString
		k.TokenTime = int(time.Now().Unix()) + 45
	}
	return nil
}

func (k *KeyCloakClient) getGenericToken(realm, username, password string) (accessTokenString string, err error) {
	headers := map[string]string{
		"Content-type": "application/x-www-form-urlencoded",
	}

	urlPath := fmt.Sprintf("/auth/realms/%s/protocol/openid-connect/token", realm)
	body := fmt.Sprintf("grant_type=password&client_id=admin-cli&username=%s&password=%s", username, password)

	resp, err := k.rawMethod("POST", urlPath, body, headers)
	if err != nil {
		return "", err
	}
	fmt.Printf("%v", resp)
	var iface interface{}

	err = json.NewDecoder(resp.Body).Decode(&iface)

	if err != nil {
		return "", err
	}

	auth, ok := iface.(map[string]interface{})

	if !ok {
		return "", fmt.Errorf("could not get auth info")
	}

	accessToken, ok := auth["access_token"]

	if !ok {
		return "", fmt.Errorf("could not get access token")
	}

	accessTokenString = accessToken.(string)

	return accessTokenString, nil
}

func (k *KeyCloakClient) rawMethod(method string, url string, body string, headers map[string]string) (*http.Response, error) {
	fullUrl := fmt.Sprintf("%s%s", k.BaseURL, url)
	fmt.Printf("\n\n%v\n%v\n%v\n%v\n\n", fullUrl, body, headers, method)
	ctx, cancel := context.WithTimeout(k.Ctx, 10*time.Second)
	defer cancel()

	r := strings.NewReader(body)

	req, err := http.NewRequestWithContext(ctx, method, fullUrl, r)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (k *KeyCloakClient) Get(url string, body string, headers map[string]string) (*http.Response, error) {
	err := k.getToken()
	if err != nil {
		return nil, err
	}
	headers["Authorization"] = fmt.Sprintf("Bearer %s", k.AccessToken)
	return k.rawMethod("GET", url, body, headers)
}

func (k *KeyCloakClient) Post(url string, body string, headers map[string]string) (*http.Response, error) {
	err := k.getToken()
	if err != nil {
		return nil, err
	}
	headers["Authorization"] = fmt.Sprintf("Bearer %s", k.AccessToken)

	return k.rawMethod("POST", url, body, headers)
}
