package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	OrgID         int    `json:"org_id"`
	DisplayName   string `json:"display_name"`
	Type          string `json:"type"`
}

var KEYCLOAK_SERVER string

func init() {
	KEYCLOAK_SERVER = os.Getenv("KEYCLOAK_SERVER")
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

func findUserById(username string) (*User, error) {
	users, err := getUsers()

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

func findUsersBy(accountNo string, adminOnly string, input *usersByInput, users *V1UserInput) ([]User, error) {
	usersList, err := getUsers()

	if err != nil {
		return nil, err
	}

	out := []User{}
	for _, user := range usersList {
		if adminOnly == "true" && !user.IsOrgAdmin {
			continue
		}
		if accountNo != "" && user.AccountNumber != accountNo {
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
		if users != nil {
			found := false
			for _, userCheck := range users.Users {
				if userCheck == user.Username {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, user)
	}
	return out, nil
}

func jwtHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/auth/realms/redhat-external/", KEYCLOAK_SERVER))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	realm := &Realm{}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &realm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, realm.PublicKey)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "no auth header found", http.StatusForbidden)
		return
	}
	if !strings.Contains(auth, "Basic") {
		http.Error(w, "auth header is not basic", http.StatusForbidden)
		return
	}

	data, err := base64.StdEncoding.DecodeString(auth[6:])

	if err != nil {
		http.Error(w, "could not split header", http.StatusForbidden)
		return
	}
	parts := strings.Split(string(data), ":")

	username := parts[0]
	password := parts[1]

	if err != nil {
		http.Error(w, fmt.Sprintf("can't create keycloak client: %s", err.Error()), http.StatusForbidden)
		return
	}

	_, err = k.getGenericToken("redhat-external", username, password)

	if err != nil {
		http.Error(w, "couldn't auth user", http.StatusForbidden)
		return
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
}

func usersV1(w http.ResponseWriter, r *http.Request) {
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
	users, err := findUsersBy("", "false", nil, filt)

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

func getUsers() (users []User, err error) {
	resp, err := k.Get("/auth/admin/realms/redhat-external/users?max=2000", "", map[string]string{})
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

		OrgIDRaw := user.Attributes["org_id"][0]
		OrgID, _ := strconv.Atoi(OrgIDRaw)

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
		})
	}
	fmt.Printf("%v", obj)
	return users, nil
}

func usersV1Handler(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	accountId := urlParts[2]
	switch {
	case urlParts[3] == "users" && r.Method == "GET":
		adminOnly := r.URL.Query().Get("admin_only")
		users, err := findUsersBy(accountId, adminOnly, nil, nil)
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
		users, err := findUsersBy(accountId, "false", filt, nil)
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

func usersV2Handler(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	accountId := urlParts[2]
	users, err := findUsersBy(accountId, "false", nil, nil)
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

func mainHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	switch {
	case r.URL.Path == "/":
		statusHandler(w, r)
	case r.URL.Path == "/v1/users":
		usersV1(w, r)
	case r.URL.Path == "/v1/jwt":
		jwtHandler(w, r)
	case r.URL.Path == "/v1/auth":
		authHandler(w, r)
	case r.URL.Path[:12] == "/v1/accounts":
		usersV1Handler(w, r)
	case r.URL.Path[:12] == "/v2/accounts":
		usersV2Handler(w, r)
	}
}

var k *KeyCloakClient

func main() {
	key, err := NewKeyCloakClient(KEYCLOAK_SERVER, "admin", "admin", context.Background(), "master")

	k = key

	if err != nil {
		log.Fatal("NOO - couldn't connect to keycloak")
	}
	http.HandleFunc("/", mainHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
