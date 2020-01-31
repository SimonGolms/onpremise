# Sentry 10 On-Premise on OpenShift

## Getting Started

### Service Account with anyuid

The following container (_name: image_) needs root permission to start and run successfully

- DeploymentConfig

  - clickhouse: `yandex/clickhouse-server:19.4`
  - kafka: `confluentinc/cp-kafka:5.1.2`
  - postgres: `postgres:9.6`
  - redis: `redis:5.0-alpine`
  - smtp: `tianon/exim4`
  - snuba-api: `getsentry/snuba:latest`
  - snuba-consumer: `getsentry/snuba:latest`
  - snuba-replacer: `getsentry/snuba:latest`
  - worker: `${SENTRY_IMAGE}`

- CronJob
  - snuba-cleanup: `getsentry/snuba:latest`

**Create Serviceaccount `useroot`**

```bash
oc create serviceaccount useroot –n <namespace>
```

**Add Serviceaccount `useroot` to the `anyuid` scc**

```bash
oc adm policy add-scc-to-user anyuid -z system:serviceaccount:<namespace>:useroot
```

_Hint: If you do not have permission to change the scc, get in contact with your cluster administrator._

More Information: https://blog.openshift.com/understanding-service-accounts-sccs/

## Provisioning

### Quickstart

Import `sentry-onpremise-quickstart-template.yaml` into your OpenShift Project and process the template.

### Customized

#### Sentry Docker Image

Import `./sentry/sentry-template.yaml` YAML file into your OpenShift project or build and provide your own sentry image.
More Information: [./sentry/README.md](./sentry/README.md)

#### Sentry On-Premise

Import `sentry-onpremise-template.yaml` into your OpenShift Project and process the template.
The template will create some `DeploymentConfigs` and some `CronJobs` and a `Job`.

## Deprovisioning

### Quickstart

```bash
$ oc delete all --selector app=<name>
oc delete pvc --selector app=<name>
oc delete configmap sentry-config
oc delete secret sentry-secret
```

### Customized

```bash
oc delete all --selector app=<name>
oc delete pvc --selector app=<name>
```
