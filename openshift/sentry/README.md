# Sentry Nightly On-Premise Docker Image

This is a customized docker image including 3rd Party Plugins that can be used by OpenShift.

## Provisioning

Import `sentry-template.yaml` into your OpenShift Project and process the template.

A `BuildConfig`, `ImageStream`, `ConfigMap` and `Secret` is created, which can be used for the further setup of the on-premise.

If you want to customize the Sentry Docker image and the other OpenShift objects, clone the repo and make the respective changes inside the template. Add or remove plugins you need.

### Environment Variables

**`SENTRY_SECRET_KEY`**

A secret key used for cryptographic functions within Sentry. This key should be unique and consistent across all running instances. You can generate a new secret key doing something like:

**`SENTRY_POSTGRES_HOST`, `SENTRY_POSTGRES_PORT`, `SENTRY_DB_NAME`, `SENTRY_DB_USER`, `SENTRY_DB_PASSWORD`**

Database credentials for your Postgres server. These values aren't needed if a linked postgres container exists.

**`SENTRY_SERVER_EMAIL`**

The email address used for `From:` in outbound emails. Default: `root@localhost`

**`SENTRY_EMAIL_HOST`, `SENTRY_EMAIL_PORT`, `SENTRY_EMAIL_USER`, `SENTRY_EMAIL_PASSWORD`, `SENTRY_EMAIL_USE_TLS`**

Connection information for an outbound smtp server. These values aren't needed if a linked `smtp` container exists.

**`SENTRY_MAILGUN_API_KEY`**

If you're using Mailgun for inbound mail, set your API key and configure a route to forward to `/api/hooks/mailgun/inbound/`.

More Information:

- https://hub.docker.com/_/sentry/

## Plugins

There are several interfaces currently available to extend Sentry. These are a work in progress and the API is not frozen.

More Information: https://docs.sentry.io/server/plugins/

### 3rd Party Plugins

#### sentry-ldap-auth

> A Django custom authentication backend for Sentry. This module extends the functionality of django-auth-ldap with Sentry specific features.

Set the following environment variables for your LDAP integration inside of the created `Secret`:

```yaml
# Example
LDAP_BIND_DN: ""
LDAP_BIND_PASSWORD: ""
LDAP_SERVER: "ldap://my.ldapserver.com"
LDAP_SELF_SIGNED_CERT: "False"
LDAP_USER_SEARCH_BASE_DN: "DC=domain,DC=com"
LDAP_USER_SEARCH_FILTER: "(&(objectClass=organizationalPerson)(|(sAMAccountName=%(user)s)(mail=%(user)s)))"
LDAP_GROUP_SEARCH_BASE_DN: "DC=domain,DC=com"
LDAP_GROUP_SEARCH_FILTER: "(objectClass=group)"
LDAP_DEFAULT_EMAIL_DOMAIN: "domain.com"
LDAP_DEFAULT_SENTRY_ORGANIZATION: "Sentry"
LDAP_SENTRY_ORGANIZATION_ROLE_TYPE: "member"
LDAP_SENTRY_GROUP_ROLE_MAPPING_OWNER: "sysadmins"
LDAP_SENTRY_GROUP_ROLE_MAPPING_MANAGER: "CN=sentry-manager,DC=domain,DC=com"
LDAP_SENTRY_GROUP_ROLE_MAPPING_ADMIN: "CN=sentry-admin,DC=domain,DC=com"
LDAP_SENTRY_GROUP_ROLE_MAPPING_MEMBER: "CN=sentry-member,DC=domain,DC=com"
LDAP_DEBUG: "True"
```

More Information: https://github.com/Banno/getsentry-ldap-auth

#### sentry-msteams

> Microsoft Teams Integration for Sentry Error Tracking Software.

Go to [https://<SENTRY_URL>/settings/<ORGANIZATION_NAME>/projects/<PROJECT_NAME>/plugins/](https://<SENTRY_URL>/settings/<ORGANIZATION_NAME>/projects/<PROJECT_NAME>/plugins/) to enable and configure the Microsoft Teams plugin

More Information: https://github.com/Neko-Design/sentry-msteams

## Deprovisioning

```bash
oc delete buildconfig --selector app=<name>
oc delete imagestream --selector app=<name>
oc delete configmap <configmap-
oc delete secret <secret-name>
```
