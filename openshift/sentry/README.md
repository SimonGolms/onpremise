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

#### sentry-auth-oidc

> An SSO provider for Sentry which enables OpenID Connect Apps authentication.

Add `https://sentry.example.com/auth/sso/` to the authorized redirect URIs (on your IdP).

Set the following environment variables for your oidc integration inside of the created `Secret`:

```yaml
# Example
OIDC_CLIENT_ID: ""
OIDC_CLIENT_SECRET: ""
OIDC_SCOPE: "openid email"
OIDC_DOMAIN: "https://accounts.google.com"
```

The OIDC_DOMAIN defines where the OIDC configuration is going to be pulled from. Basically it specifies the OIDC server and adds the path `.well-known/openid-configuration` to it. That's where different endpoint paths can be found.

You can also define `OIDC_ISSUER` to change the default provider name in the UI, even when the `OIDC_DOMAIN` is set.

If your provider doesn't support the `OIDC_DOMAIN`, then you have to set these required endpoints by yourself (autorization_endpoint, token_endpoint, userinfo_endpoint, issuer).

```yaml
# Example
OIDC_AUTHORIZATION_ENDPOINT: "https://accounts.google.com/o/oauth2/v2/auth"
OIDC_TOKEN_ENDPOINT: "https://www.googleapis.com/oauth2/v4/token"
OIDC_USERINFO_ENDPOINT: "[openid email](https://www.googleapis.com/oauth2/v3/userinfo)"
OIDC_ISSUER: "Google"
```

#### sentry-msteams

> Microsoft Teams Integration for Sentry Error Tracking Software.

Go to [https://<SENTRY_URL>/settings/<ORGANIZATION_NAME>/projects/<PROJECT_NAME>/plugins/](https://<SENTRY_URL>/settings/<ORGANIZATION_NAME>/projects/<PROJECT_NAME>/plugins/) to enable and configure the Microsoft Teams plugin

More Information: https://github.com/Neko-Design/sentry-msteams

## Deprovisioning

```bash
oc delete all -l app=<name>
oc delete configmap <configmap-name>
oc delete secret <secret-name>
# ATTTENTION! The following command is only optional and will permanently delete all of your data.
oc delete pvc -l app=<name>
```
