# Mock BOP service

This service is used to replace the [BOP](https://github.com/RedHatInsights/backoffice-proxy) service in Ephemeral environments.

It starts up an HTTP server on port `8090`, and forwards requests to different endpoints depending on the URL paths the user requests.

It is meant to be run alongside a [Keycloak](https://www.keycloak.org) service, where it can fetch and print information about users and realms.

## Pre-requisites

While not essential for running this service, you'll need a local Keycloak server with a pre-configured realm named `redhat-external` on it, and some users, with the following attributes:

- `is_active`: type: Boolean
- `is_org_admin`: type: Boolean
- `is_internal`: type: Boolean
- `account_id`: type: String
- `org_id`: type: String
- `entitlements`: type: String
- `account_number`: type: String

## List of supported paths

The current list of supported paths is:

- `/` : Empty endpoint, used as a status check endpoint.
- `/v1/users` : only `POST` requests are allowed. Used to fetch Keycloak users
- `/v1/jwt` : sends a `GET` request against the `KEYCLOAK_SERVER` URL and prints the
              `redhat-external` realm public key
- `/v1/auth` : it expects a basic Authorization Header to be sent with username and
               password, and uses it to request a token from the `redhat-external`
               realm from the `KEYCLOAK_SERVER` URL for that user. Then returns the
               user entity.
- `/v1/accounts` : handles `POST` and `GET` requests for querying users for a specific account
- `/v2/accounts` : expects a GET request with query params defining filters to fetch users on Keycloak
- `/api/entitlements/v1/services` : prints a user's entitlements list based on the
                                    provided Identity header (only Basic Auth is
                                    supported). if the enviroment variable `ALL_PASS`
                                    is found then a fixed JSON object with
                                    entitlements is printed instead.


## How to run

You'll need a Keycloak Server running for the Keycloak-related requests to succed,
and pass in the Server URL, Admin username and password using the `KEYCLOAK_SERVER`,
`KEYCLOAK_USERNAME` and `KEYCLOAK_PASSWORD` environment variables respectively.

The current supported version of Keycloak is: UNKNOWN (probably >= 17.1.0)

### Locally

## Keycloak

It is recommended if you simply spin a container with a Keycloak server:


```shell
# TODO: provide realm and users JSON export and instructions on how to auto-import

podman run -it --name keycloak -p 8080:8080 -e KEYCLOAK_ADMIN_USER=admin -e KEYCLOAK_ADMIN_PASSWORD=change_me quay.io/keycloak/keycloak:17.0.1
```

## BOP

You can run this locally just by running:

```sh

$ go build

$ KEYCLOAK_SERVER='http://localhost:8080' KEYCLOAK_USERNAME='admin' KEYCLOAK_PASSWORD='change_it' ./mbop
```

You can also build the image container and run it locally with podman:

```
podman build -t localhost/mbop:dev .

podman run -it --rm --name mbop -p 8090:8090 -e KEYCLOAK_SERVER='http://localhost:8080' KEYCLOAK_USERNAME='admin' KEYCLOAK_PASSWORD='change_it'  localhost/mbop:dev
```

## How to test ?

Simply run

```
go test
```