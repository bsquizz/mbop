package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
)

type User struct {
	Username      string `json:"username"`
	ID            int    `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	AccountNumber string `json:"account_number"`
	AddressString string `json:"address_string"`
	IsActive      bool   `json:"is_active"`
	IsOrgAdmin    bool   `json:"is_org_admin"`
	IsInternal    bool   `json:"is_internal"`
	Locale        string `json:"locale"`
	OrgID         string `json:"org_id"`
	DisplayName   string `json:"display_name"`
	Type          string `json:"type"`
	Entitlements  string `json:"entitlements"`
}

type JSONStruct struct {
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

type usersByInput struct {
	PrimaryEmail        string `json:"primaryEmail"`
	EmailStartsWith     string `json:"emailStartsWith"`
	PrincipalStartsWith string `json:"principalStartsWith"`
}

type Resp struct {
	User      User   `json:"user"`
	Mechanism string `json:"mechanism"`
}

type AccV2Resp struct {
	Users     []User `json:"users"`
	UserCount int    `json:"userCount"`
}

type Realm struct {
	Realm     string `json:"realm"`
	PublicKey string `json:"public_key"`
}

type V1UserInput struct {
	Users []string `json:"users"`
}

func (m *MBOPServer) findUserById(username string) (*User, error) {
	users, err := m.getUsers()

	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("User is not known")
}

func (m *MBOPServer) findUsersBy(accountNo string, orgId string, adminOnly string, status string, limit int, sortOrder string, queryBy string, input *usersByInput, users *V1UserInput) ([]User, error) {
	usersList, err := m.getUsers()

	if err != nil {
		return nil, err
	}

	out := []User{}
	for _, user := range usersList {
		// When adminOnly is true, parameter “status” is ignored
		if adminOnly == "true" && !user.IsOrgAdmin {
			continue
		} else {
			if status == "disabled" {
				if user.IsActive {
					continue
				}
			} else if status == "enabled" {
				if !user.IsActive {
					continue
				}
			} else if status != "all" {
				if !user.IsActive {
					continue
				}
			}
		}
		if accountNo != "" && user.AccountNumber != accountNo {
			continue
		}
		if orgId != "" && user.OrgID != orgId {
			continue
		}
		if input != nil {
			if input.PrimaryEmail != "" && user.Email != input.PrimaryEmail {
				continue
			}
			if input.EmailStartsWith != "" && !strings.HasPrefix(user.Email, input.EmailStartsWith) {
				continue
			}
			if input.PrincipalStartsWith != "" && !strings.HasPrefix(user.Username, input.PrincipalStartsWith) {
				continue
			}
		}
		if users != nil && users.Users != nil {
			found := false
			for _, userCheck := range users.Users {
				if queryBy == "userId" {
					if strings.EqualFold(userCheck, strconv.Itoa(user.ID)) {
						found = true
					}
				} else {
					if strings.EqualFold(userCheck, user.Username) {
						found = true
					}
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, user)

		if limit > 0 && len(out) >= limit {
			break
		}
	}

	if sortOrder == "des" {
		sort.Slice(out, func(i, j int) bool {
			return strings.Compare(out[i].Username, out[j].Username) == 1
		})
	}

	return out, nil
}

func (m *MBOPServer) jwtHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := m.getJWT("redhat-external")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	fmt.Fprintf(w, resp.PublicKey)
}

func (m *MBOPServer) getJWT(realm string) (*JSONStruct, error) {
	resp, err := http.Get(fmt.Sprintf("%s/auth/realms/%s/", m.server, realm))

	if err != nil {
		return nil, err
	}

	bdata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jsonstruct := &JSONStruct{}
	err = json.Unmarshal(bdata, jsonstruct)
	if err != nil {
		return nil, err
	}

	return jsonstruct, nil
}

func (m *MBOPServer) getUser(w http.ResponseWriter, r *http.Request) (*User, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return &User{}, fmt.Errorf("no auth header found")
	}
	if !strings.Contains(auth, "Basic") {
		return &User{}, fmt.Errorf("auth header is not basic")
	}

	data, err := base64.StdEncoding.DecodeString(auth[6:])

	if err != nil {
		return &User{}, fmt.Errorf("could not split header")
	}
	parts := strings.Split(string(data), ":")

	username := parts[0]
	password := parts[1]

	if err != nil {
		return &User{}, fmt.Errorf("can't create keycloak client: %s", err.Error())
	}

	oauthClientConfig := clientcredentials.Config{
		ClientID:       "admin-cli",
		ClientSecret:   "",
		TokenURL:       path.Join(m.server.String(), "auth/realms/redhat-external/protocol/openid-connect/token"),
		EndpointParams: url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}},
	}

	k := oauthClientConfig.Client(context.Background())
	resp, err := k.Get(path.Join(m.server.String(), "auth/realms/redhat-external/account/"))

	if err != nil {
		return &User{}, fmt.Errorf("couldn't auth user: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return &User{}, fmt.Errorf("user unauthorized: %d", resp.StatusCode)
	}

	userObj, err := m.findUserById(username)

	if err != nil {
		return &User{}, fmt.Errorf("couldn't find user: %s", err.Error())
	}
	return userObj, nil
}

func (m *MBOPServer) authHandler(w http.ResponseWriter, r *http.Request) {

	userObj, err := m.getUser(w, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't auth user: %s", err.Error()), http.StatusForbidden)
		return
	}

	respObj := Resp{
		User:      *userObj,
		Mechanism: "Basic",
	}
	str, err := json.Marshal(respObj)
	if err != nil {
		http.Error(w, "could not create response", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(str))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
}

func (m *MBOPServer) usersV1(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filt := &V1UserInput{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "malformed input", http.StatusInternalServerError)
		return
	}
	if string(data) != "" {
		err = json.Unmarshal(data, filt)
		if err != nil {
			http.Error(w, "malformed input", http.StatusInternalServerError)
			return
		}
	}
	adminOnly := r.URL.Query().Get("admin_only")
	status := r.URL.Query().Get("status")
	sortOrder := r.URL.Query().Get("sortOrder")
	queryBy := r.URL.Query().Get("queryBy")
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 0
	}
	users, err := m.findUsersBy("", "", adminOnly, status, limit, sortOrder, queryBy, nil, filt)

	if err != nil {
		http.Error(w, "could not get response", http.StatusInternalServerError)
		return
	}

	str, err := json.Marshal(users)
	if err != nil {
		http.Error(w, "could not create response", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(str))
}

type usersSpec struct {
	Username   string              `json:"username"`
	Enabled    bool                `json:"enabled"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

func (m *MBOPServer) getUsers() (users []User, err error) {
	resp, err := m.Client.Get(path.Join(m.server.String(), "/auth/admin/realms/redhat-external/users?max=2000"))
	if err != nil {
		fmt.Printf("\n\n%s\n\n", err.Error())
	}

	obj := &[]usersSpec{}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, obj)

	if err != nil {
		return nil, err
	}

	users = []User{}

	for _, user := range *obj {
		IsActiveRaw := user.Attributes["is_active"][0]
		IsActive, _ := strconv.ParseBool(IsActiveRaw)

		IsOrgAdminRaw := user.Attributes["is_org_admin"][0]
		IsOrgAdmin, _ := strconv.ParseBool(IsOrgAdminRaw)

		IsInternalRaw := user.Attributes["is_org_admin"][0]
		IsInternal, _ := strconv.ParseBool(IsInternalRaw)

		IDRaw := user.Attributes["account_id"][0]
		ID, _ := strconv.Atoi(IDRaw)

		OrgID := user.Attributes["org_id"][0]

		var entitle string

		if len(user.Attributes["newEntitlements"]) != 0 {
			entitle = fmt.Sprintf("{%s}", strings.Join(user.Attributes["newEntitlements"], ","))

		} else {
			entitle = user.Attributes["entitlements"][0]
		}

		users = append(users, User{
			Username:      user.Username,
			ID:            ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			AccountNumber: user.Attributes["account_number"][0],
			AddressString: "unknown",
			IsActive:      IsActive,
			IsOrgAdmin:    IsOrgAdmin,
			IsInternal:    IsInternal,
			Locale:        "en_US",
			OrgID:         OrgID,
			DisplayName:   user.FirstName,
			Type:          "User",
			Entitlements:  entitle,
		})
	}
	fmt.Printf("%v", obj)
	return users, nil
}

func (m *MBOPServer) usersV1Handler(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	accountId := urlParts[2]
	switch {
	case urlParts[3] == "users" && r.Method == "GET":
		adminOnly := r.URL.Query().Get("admin_only")
		status := r.URL.Query().Get("status")
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			limit = 0
		}

		users, err := m.findUsersBy(accountId, "", adminOnly, status, limit, "", "", nil, nil)
		if err != nil {
			http.Error(w, "could not get response", http.StatusInternalServerError)
			return
		}

		str, err := json.Marshal(users)
		if err != nil {
			http.Error(w, "could not create response", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(str))
	case urlParts[3] == "usersBy" && r.Method == "POST":
		filt := &usersByInput{}
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "malformed input", http.StatusInternalServerError)
			return
		}
		if string(data) != "" {
			err = json.Unmarshal(data, filt)
			if err != nil {
				http.Error(w, "malformed input", http.StatusInternalServerError)
				return
			}
		}
		adminOnly := r.URL.Query().Get("admin_only")
		status := r.URL.Query().Get("status")
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			limit = 0
		}

		users, err := m.findUsersBy(accountId, "", adminOnly, status, limit, "", "", filt, nil)
		if err != nil {
			http.Error(w, "could not get response", http.StatusInternalServerError)
			return
		}

		str, err := json.Marshal(users)
		if err != nil {
			http.Error(w, "could not create response", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(str))
	}
}

func (m *MBOPServer) usersV2V3Handler(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	accountId := ""
	orgId := ""
	if urlParts[0] == "v2" {
		accountId = urlParts[2]
	} else {
		orgId = urlParts[2]
	}
	adminOnly := r.URL.Query().Get("admin_only")
	status := r.URL.Query().Get("status")
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 0
	}

	obj := &usersByInput{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	if len(data) > 0 {
		err = json.Unmarshal(data, obj)
		if err != nil {
			return
		}
	}

	users, err := m.findUsersBy(accountId, orgId, adminOnly, status, limit, "", "", obj, nil)

	if err != nil {
		http.Error(w, "could not get response", http.StatusInternalServerError)
		return
	}
	respObj := AccV2Resp{
		Users:     users,
		UserCount: len(users),
	}
	str, err := json.Marshal(respObj)
	if err != nil {
		http.Error(w, "could not create response", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(str))
}

func (m *MBOPServer) entitlements(w http.ResponseWriter, r *http.Request) {
	ALL_PASS := os.Getenv("ALL_PASS")

	if ALL_PASS != "" {
		fmt.Printf("ALL_PASS")
		fmt.Fprint(w, "{\"ansible\": {\"is_entitled\": true, \"is_trial\": false}, \"cost_management\": {\"is_entitled\": true, \"is_trial\": false}, \"insights\": {\"is_entitled\": true, \"is_trial\": false}, \"advisor\": {\"is_entitled\": true, \"is_trial\": false}, \"migrations\": {\"is_entitled\": true, \"is_trial\": false}, \"openshift\": {\"is_entitled\": true, \"is_trial\": false}, \"settings\": {\"is_entitled\": true, \"is_trial\": false}, \"smart_management\": {\"is_entitled\": true, \"is_trial\": false}, \"subscriptions\": {\"is_entitled\": true, \"is_trial\": false}, \"user_preferences\": {\"is_entitled\": true, \"is_trial\": false}, \"notifications\": {\"is_entitled\": true, \"is_trial\": false}, \"integrations\": {\"is_entitled\": true, \"is_trial\": false}, \"automation_analytics\": {\"is_entitled\": true, \"is_trial\": false}}")
		return
	}

	userObj, err := m.getUser(w, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't auth user: %s", err.Error()), http.StatusForbidden)
		return
	}

	fmt.Fprint(w, string(userObj.Entitlements))
}

func (m *MBOPServer) mainHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))
	switch {
	case r.URL.Path == "/":
		statusHandler(w, r)
	case r.URL.Path == "/v1/users":
		m.usersV1(w, r)
	case r.URL.Path == "/v1/jwt":
		m.jwtHandler(w, r)
	case r.URL.Path == "/v1/auth":
		m.authHandler(w, r)
	case r.URL.Path[:12] == "/v1/accounts":
		m.usersV1Handler(w, r)
	case r.URL.Path[:12] == "/v2/accounts":
		m.usersV2V3Handler(w, r)
	case r.URL.Path[:12] == "/v3/accounts":
		m.usersV2V3Handler(w, r)
	case r.URL.Path == "/api/entitlements/v1/services":
		m.entitlements(w, r)
	}
}

var log logr.Logger

func (m *MBOPServer) getMux() *http.ServeMux {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	log = zapr.NewLogger(zapLog)

	oauthClientConfig := clientcredentials.Config{
		ClientID:       "admin-cli",
		ClientSecret:   "",
		TokenURL:       path.Join(m.server.String(), "/auth/realms/master/protocol/openid-connect/token"),
		EndpointParams: url.Values{"grant_type": {"password"}, "username": {m.username}, "password": {m.password}},
	}

	m.Client = oauthClientConfig.Client(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc("/", m.mainHandler)
	return mux
}

type MBOPServer struct {
	server   *url.URL
	username string
	password string
	Client   *http.Client
}

func MakeNewMBOPServer() *MBOPServer {
	KEYCLOAK_USERNAME := os.Getenv("KEYCLOAK_USERNAME")
	KEYCLOAK_PASSWORD := os.Getenv("KEYCLOAK_PASSWORD")
	if KEYCLOAK_USERNAME == "" {
		KEYCLOAK_USERNAME = "admin"
	}
	if KEYCLOAK_PASSWORD == "" {
		KEYCLOAK_PASSWORD = "admin"
	}

	keyServer, err := url.Parse(os.Getenv("KEYCLOAK_SERVER"))
	if err != nil {
		fmt.Printf("KEYCLOAK server URL was malformed")
		os.Exit(127)
	}

	return &MBOPServer{
		server:   keyServer,
		username: KEYCLOAK_USERNAME,
		password: KEYCLOAK_PASSWORD,
	}
}

func main() {
	mbServer := MakeNewMBOPServer()

	if err := http.ListenAndServe(":8090", mbServer.getMux()); err != nil {
		log.Error(err, "reason", "server couldn't start")
	}
}
