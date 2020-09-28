FROM getsentry/sentry:latest

# Install required dependencies for plugin sentry-ldap-auth 
RUN apt-get update && \
    apt-get -y install gcc mono-mcs python-dev libldap2-dev libsasl2-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /usr/src/sentry

# Hook for installing additional plugins
RUN if [ -s /usr/src/sentry/requirements.txt ]; then pip install -r /usr/src/sentry/requirements.txt; fi
