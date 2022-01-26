#!/usr/bin/python
import json
import requests
import sys
import getopt

class updateUserStruct:
    def __init__(self, id, enabled, username, firstName, lastName, email, attributes):
        self.id = id
        self.enabled = enabled
        self.username = username
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.attributes = attributes

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

class createUserStruct:
    def __init__(self, enabled, username, firstname, lastname, email, attributes, credentials):
        self.enabled = enabled
        self.username = username
        self.firstName = firstname
        self.lastName = lastname
        self.email = email
        self.attributes = attributes
        self.credentials = credentials

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)


class userAttributes:
    def __init__(self, first_name, last_name, account_id, account_number, org_id, is_internal, is_org_admin, is_active, entitlements):
        self.first_name = first_name
        self.last_name = last_name
        self.account_id = account_id
        self.account_number = account_number
        self.org_id = org_id
        self.is_internal = is_internal
        self.is_org_admin = is_org_admin
        self.is_active = is_active
        self.entitlements = entitlements


class userCredentials:
    def __init__(self, temporary, type, value):
        self.temporary = temporary
        self.type = type
        self.value = value

    def toJson(self):
        return [{'value': self.value, 'type': self.type, 'temporary': self.temporary}]


class KeyCloakClient:
    def __init__(self, baseUrl, username, password, accesstoken):
        self.BaseURL = baseUrl
        self.Username = username
        self.Password = password
        self.AccessToken = accesstoken

    def startClient(self):
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        response = self.rawMethod("POST", "/auth/realms/master/protocol/openid-connect/token",
                        "grant_type=password&client_id=admin-cli&username={}&password={}".format(self.Username, self.Password), headers)
        json_response = response.json()
        self.AccessToken = json_response['access_token']

    def Get(self, url, body, headers):
        headers["Authorization"] = "Bearer {}".format(self.AccessToken)
        return self.rawMethod("GET", url, body, headers)

    def Post(self, url, body, headers):
        headers["Authorization"] = "Bearer {}".format(self.AccessToken)
        return self.rawMethod("POST", url, body, headers)

    def Put(self, url, body, headers):
        headers["Authorization"] = "Bearer {}".format(self.AccessToken)
        return self.rawMethod("PUT", url, body, headers)

    def putUser(self, realm_name, user):
        headers = {"Content-type": "application/json"}
        body = user.toJson()
        response = self.Put("/auth/admin/realms/{}/users/{}".format(realm_name, user.id), body, headers)

    def doesUserExist(self, realm_name, requestedUser):
        return_dict = dict()
        headers = {}
        response = self.Get("/auth/admin/realms/{}/users/".format(realm_name), "", headers)
        for user in response.json():
            if user['username'] == requestedUser.username:
                return_dict['user'] = user
                return_dict['bool'] = True
                return return_dict

        return_dict['user'] = requestedUser
        return_dict['id'] = 0
        return_dict['bool'] = False
        return return_dict

    def rawMethod(self, method, url, body, headers):
        fullUrl = self.BaseURL+url
        try:
            if (method == "GET"):
                r = requests.get(fullUrl, headers=headers)
            elif (method == "POST"):
                r = requests.post(fullUrl, data=body, headers=headers)
            elif (method == "PUT"):
                r = requests.put(fullUrl, data=body, headers=headers)
            else:
                print("Not supported at this time")
                exit(1)
        except requests.exceptions.RequestException as e:
            print("Error in request")
            raise SystemExit(e)
        return r

    def addUser(self, realm_name, user):
        rtn_dict = self.doesUserExist(realm_name, user)
        if not rtn_dict['bool']:
            headers = {"Content-type": "application/json"}
            body = user.toJson()
            response = self.Post("/auth/admin/realms/{}/users".format(realm_name), body, headers)
            return rtn_dict['user']
        else:
            #print("User with username already exists.")
            return rtn_dict['user']


class AuthStruct:
    def __init__(self, accesstoken):
        self.AccessToken = accesstoken


def newKeyCloakClient(BaseUrl, Username, Password):
    client = KeyCloakClient(BaseUrl, Username, Password, "")
    client.startClient()
    return client


def createUsers(keycloak):
    test_attributes = userAttributes("Test", "Tester", "12345", "12345", "12345", "false", "true", "true",
                                     "{\"insights\": {\"is_entitled\": true, \"is_trial\": false}}")
    test_credentials = userCredentials("False", "password", "secret")

    admin_attributes = userAttributes("Admin", "Tester", "54321", "54321", "54321", "false", "true", "true",
                                     "{\"insights\": {\"is_entitled\": true, \"is_trial\": false}}")
    admin_credentials = userCredentials("False", "password", "secret")

    nonadmin_attributes = userAttributes("NonAdmin", "Tester", "12345", "12345", "12345", "false", "false", "true",
                                      "{\"insights\": {\"is_entitled\": true, \"is_trial\": false}}")
    nonadmin_credentials = userCredentials("False", "password", "secret")

    users = [[test_attributes, test_credentials], [admin_attributes, admin_credentials], [nonadmin_attributes, nonadmin_credentials]]

    for u in users:
        add_user = createUserStruct("true", u[0].first_name.lower(), u[0].first_name, u[0].last_name, u[0].first_name.lower()+"@redhat.com", u[0], u[1].toJson())
        print("Adding: ", u[0].first_name)
        new_user = keycloak.addUser("redhat-external", add_user)
        new_user_entitlements = ["\"ansible\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"cost_management\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"insights\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"advisor\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"migrations\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"openshift\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"settings\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"smart_management\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"subscriptions\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"user_preferences\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"notifications\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"integrations\": {\"is_entitled\": True, \"is_trial\": False}",
                                 "\"automation_analytics\": {\"is_entitled\": True, \"is_trial\": False }"]

        new_user = keycloak.addUser("redhat-external", add_user)
        update_user = updateUserStruct(new_user['id'], new_user['enabled'], new_user['username'],
                                       new_user['firstName'], new_user['lastName'], new_user['email'],
                                       new_user['attributes'])

        update_user.attributes['newEntitlements'] = new_user_entitlements
        keycloak.putUser("redhat-external", update_user)


def main(argv):
    args = sys.argv[1:]
    hostname = ''
    username = ''
    password = ''
    try:
        opts, args = getopt.getopt(argv, "h:u:p:", ["host=", "username=", "password="])
    except getopt.GetoptError:
        print('usage: keycloak_add_users.py -host <host_url> -username <admin_username> -pass <admin_password>')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--host"):
            hostname = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg

    keycloak = newKeyCloakClient(hostname, username, password)
    createUsers(keycloak)


if __name__ == "__main__":
    main(sys.argv[1:])

