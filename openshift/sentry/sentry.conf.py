# This file is just Python, with a touch of Django which means
# you can inherit and tweak settings to your hearts content.

# For Docker, the following environment variables are supported:
#  SENTRY_POSTGRES_HOST
#  SENTRY_POSTGRES_PORT
#  SENTRY_DB_NAME
#  SENTRY_DB_USER
#  SENTRY_DB_PASSWORD
#  SENTRY_RABBITMQ_HOST
#  SENTRY_RABBITMQ_USERNAME
#  SENTRY_RABBITMQ_PASSWORD
#  SENTRY_RABBITMQ_VHOST
#  SENTRY_REDIS_HOST
#  SENTRY_REDIS_PASSWORD
#  SENTRY_REDIS_PORT
#  SENTRY_REDIS_DB
#  SENTRY_MEMCACHED_HOST
#  SENTRY_MEMCACHED_PORT
#  SENTRY_FILESTORE_DIR
#  SENTRY_SERVER_EMAIL
#  SENTRY_EMAIL_HOST
#  SENTRY_EMAIL_PORT
#  SENTRY_EMAIL_USER
#  SENTRY_EMAIL_PASSWORD
#  SENTRY_EMAIL_USE_TLS
#  SENTRY_ENABLE_EMAIL_REPLIES
#  SENTRY_SMTP_HOSTNAME
#  SENTRY_MAILGUN_API_KEY
#  SENTRY_SINGLE_ORGANIZATION
#  SENTRY_SECRET_KEY

from sentry.conf.server import *  # NOQA
from sentry.utils.types import Bool


# Generously adapted from pynetlinux: https://git.io/JJmga
def get_internal_network():
    import ctypes
    import fcntl
    import math
    import socket
    import struct

    iface = "eth0"
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("16sH14s", iface, socket.AF_INET, b"\x00" * 14)

    try:
        ip = struct.unpack(
            "!I", struct.unpack("16sH2x4s8x", fcntl.ioctl(sockfd, 0x8915, ifreq))[2]
        )[0]
        netmask = socket.ntohl(
            struct.unpack("16sH2xI8x", fcntl.ioctl(sockfd, 0x891B, ifreq))[2]
        )
    except IOError:
        return ()
    base = socket.inet_ntoa(struct.pack("!I", ip & netmask))
    netmask_bits = 32 - int(round(math.log(ctypes.c_uint32(~netmask).value + 1, 2), 1))
    return ("{0:s}/{1:d}".format(base, netmask_bits),)


INTERNAL_SYSTEM_IPS = get_internal_network()

postgres = env('SENTRY_POSTGRES_HOST') or (
    env('POSTGRES_PORT_5432_TCP_ADDR') and 'postgres')
if postgres:
    DATABASES = {
        'default': {
            'ENGINE': 'sentry.db.postgres',
            'NAME': (
                env('SENTRY_DB_NAME')
                or env('POSTGRES_ENV_POSTGRES_USER')
                or 'postgres'
            ),
            'USER': (
                env('SENTRY_DB_USER')
                or env('POSTGRES_ENV_POSTGRES_USER')
                or 'postgres'
            ),
            'PASSWORD': (
                env('SENTRY_DB_PASSWORD')
                or env('POSTGRES_ENV_POSTGRES_PASSWORD')
                or ''
            ),
            'HOST': postgres,
            'PORT': (
                env('SENTRY_POSTGRES_PORT')
                or ''
            ),
        },
    }


# You should not change this setting after your database has been created
# unless you have altered all schemas first
SENTRY_USE_BIG_INTS = True

# If you're expecting any kind of real traffic on Sentry, we highly recommend
# configuring the CACHES and Redis settings

###########
# General #
###########

# Instruct Sentry that this install intends to be run by a single organization
# and thus various UI optimizations should be enabled.
SENTRY_SINGLE_ORGANIZATION = Bool(env('SENTRY_SINGLE_ORGANIZATION', True))

SENTRY_OPTIONS["system.event-retention-days"] = int(env(
    'SENTRY_EVENT_RETENTION_DAYS', "90"))

#########
# Redis #
#########

# Generic Redis configuration used as defaults for various things including:
# Buffers, Quotas, TSDB

SENTRY_OPTIONS["redis.clusters"] = {
    "default": {
        "hosts": {0: {"host": "redis", "password": "", "port": "6379", "db": "0"}}
    }
}

#########
# Queue #
#########

# See https://docs.getsentry.com/on-premise/server/queue/ for more
# information on configuring your queue broker and workers. Sentry relies
# on a Python framework called Celery to manage queues.

rabbitmq_host = None
if rabbitmq_host:
    BROKER_URL = "amqp://{username}:{password}@{host}/{vhost}".format(
        username="guest", password="guest", host=rabbitmq_host, vhost="/"
    )
else:
    BROKER_URL = "redis://:{password}@{host}:{port}/{db}".format(
        **SENTRY_OPTIONS["redis.clusters"]["default"]["hosts"][0]
    )


#########
# Cache #
#########

# Sentry currently utilizes two separate mechanisms. While CACHES is not a
# requirement, it will optimize several high throughput patterns.

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.memcached.MemcachedCache",
        "LOCATION": ["memcached:11211"],
        "TIMEOUT": 3600,
    }
}

# A primary cache is required for things such as processing events
SENTRY_CACHE = "sentry.cache.redis.RedisCache"

DEFAULT_KAFKA_OPTIONS = {
    "bootstrap.servers": "kafka-service:9092",
    "message.max.bytes": 50000000,
    "socket.timeout.ms": 1000,
}

SENTRY_EVENTSTREAM = "sentry.eventstream.kafka.KafkaEventStream"
SENTRY_EVENTSTREAM_OPTIONS = {"producer_configuration": DEFAULT_KAFKA_OPTIONS}

KAFKA_CLUSTERS["default"] = DEFAULT_KAFKA_OPTIONS

###############
# Rate Limits #
###############

# Rate limits apply to notification handlers and are enforced per-project
# automatically.

SENTRY_RATELIMITER = "sentry.ratelimits.redis.RedisRateLimiter"

##################
# Update Buffers #
##################

# Buffers (combined with queueing) act as an intermediate layer between the
# database and the storage API. They will greatly improve efficiency on large
# numbers of the same events being sent to the API in a short amount of time.
# (read: if you send any kind of real data to Sentry, you should enable buffers)

SENTRY_BUFFER = "sentry.buffer.redis.RedisBuffer"

##########
# Quotas #
##########

# Quotas allow you to rate limit individual projects or the Sentry install as
# a whole.

SENTRY_QUOTAS = "sentry.quotas.redis.RedisQuota"

########
# TSDB #
########

# The TSDB is used for building charts as well as making things like per-rate
# alerts possible.

SENTRY_TSDB = "sentry.tsdb.redissnuba.RedisSnubaTSDB"

#########
# SNUBA #
#########

SENTRY_SEARCH = "sentry.search.snuba.EventsDatasetSnubaSearchBackend"
SENTRY_SEARCH_OPTIONS = {}
SENTRY_TAGSTORE_OPTIONS = {}

###########
# Digests #
###########

# The digest backend powers notification summaries.

SENTRY_DIGESTS = "sentry.digests.backends.redis.RedisBackend"

##############
# Web Server #
##############

SENTRY_WEB_HOST = "0.0.0.0"
SENTRY_WEB_PORT = 9000
SENTRY_WEB_OPTIONS = {
    "http": "%s:%s" % (SENTRY_WEB_HOST, SENTRY_WEB_PORT),
    "protocol": "uwsgi",
    # This is needed in order to prevent https://git.io/fj7Lw
    "uwsgi-socket": None,
    "so-keepalive": True,
    # Keep this between 15s-75s as that's what Relay supports
    "http-keepalive": 15,
    "http-chunked-input": True,
    # the number of web workers
    "workers": 3,
    "threads": 4,
    "memory-report": False,
    # Some stuff so uwsgi will cycle workers sensibly
    "max-requests": 100000,
    "max-requests-delta": 500,
    "max-worker-lifetime": 86400,
    # Duplicate options from sentry default just so we don't get
    # bit by sentry changing a default value that we depend on.
    "thunder-lock": True,
    "log-x-forwarded-for": False,
    "buffer-size": 32768,
    "limit-post": 209715200,
    "disable-logging": True,
    "reload-on-rss": 600,
    "ignore-sigpipe": True,
    "ignore-write-errors": True,
    "disable-write-exception": True,
}

###########
# SSL/TLS #
###########

# If you're using a reverse SSL proxy, you should enable the X-Forwarded-Proto
# header and enable the settings below

# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SOCIAL_AUTH_REDIRECT_IS_HTTPS = True

# End of SSL/TLS settings

###############
# Mail Server #
###############

email = env('SENTRY_EMAIL_HOST') or (env('SMTP_PORT_25_TCP_ADDR') and 'smtp')
if email:
    SENTRY_OPTIONS['mail.backend'] = 'smtp'
    SENTRY_OPTIONS['mail.host'] = email
    SENTRY_OPTIONS['mail.password'] = env('SENTRY_EMAIL_PASSWORD') or ''
    SENTRY_OPTIONS['mail.username'] = env('SENTRY_EMAIL_USER') or ''
    SENTRY_OPTIONS['mail.port'] = int(env('SENTRY_EMAIL_PORT') or 25)
    SENTRY_OPTIONS['mail.use-tls'] = Bool(env('SENTRY_EMAIL_USE_TLS', False))
else:
    SENTRY_OPTIONS['mail.backend'] = 'dummy'

# The email address to send on behalf of
SENTRY_OPTIONS['mail.from'] = env('SENTRY_SERVER_EMAIL') or 'root@localhost'

# If you're using mailgun for inbound mail, set your API key and configure a
# route to forward to /api/hooks/mailgun/inbound/
SENTRY_OPTIONS['mail.mailgun-api-key'] = env('SENTRY_MAILGUN_API_KEY') or ''

# If you specify a MAILGUN_API_KEY, you definitely want EMAIL_REPLIES
if SENTRY_OPTIONS['mail.mailgun-api-key']:
    SENTRY_OPTIONS['mail.enable-replies'] = True
else:
    SENTRY_OPTIONS['mail.enable-replies'] = Bool(
        env('SENTRY_ENABLE_EMAIL_REPLIES', False))

if SENTRY_OPTIONS['mail.enable-replies']:
    SENTRY_OPTIONS['mail.reply-hostname'] = env('SENTRY_SMTP_HOSTNAME') or ''

# If this value ever becomes compromised, it's important to regenerate your
# SENTRY_SECRET_KEY. Changing this value will result in all current sessions
# being invalidated.
secret_key = env('SENTRY_SECRET_KEY')
if not secret_key:
    raise Exception(
        'Error: SENTRY_SECRET_KEY is undefined, run `generate-secret-key` and set to -e SENTRY_SECRET_KEY')

if 'SENTRY_RUNNING_UWSGI' not in os.environ and len(secret_key) < 32:
    print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    print('!!                    CAUTION                       !!')
    print('!! Your SENTRY_SECRET_KEY is potentially insecure.  !!')
    print('!!    We recommend at least 32 characters long.     !!')
    print('!!     Regenerate with `generate-secret-key`.       !!')
    print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

SENTRY_OPTIONS['system.secret-key'] = secret_key

############
# Features #
############

SENTRY_FEATURES["projects:sample-events"] = False
SENTRY_FEATURES.update(
    {
        feature: True
        for feature in (
            "organizations:discover",
            "organizations:events",
            "organizations:global-views",
            "organizations:integrations-issue-basic",
            "organizations:integrations-issue-sync",
            "organizations:invite-members",
            "organizations:sso-basic",
            "organizations:sso-rippling",
            "organizations:sso-saml2",
            "organizations:performance-view",
            "projects:custom-inbound-filters",
            "projects:data-forwarding",
            "projects:discard-groups",
            "projects:plugins",
            "projects:rate-limits",
            "projects:servicehooks",
        )
    }
)

######################
# GitHub Integration #
#####################

# GITHUB_APP_ID = 'YOUR_GITHUB_APP_ID'
# GITHUB_API_SECRET = 'YOUR_GITHUB_API_SECRET'
# GITHUB_EXTENDED_PERMISSIONS = ['repo']

#########################
# Bitbucket Integration #
########################

# BITBUCKET_CONSUMER_KEY = 'YOUR_BITBUCKET_CONSUMER_KEY'
# BITBUCKET_CONSUMER_SECRET = 'YOUR_BITBUCKET_CONSUMER_SECRET'


#################
# LDAP settings #
#################

# sentry_ldap = env('LDAP_SERVER') or False

# if sentry_ldap:
#     import ldap
#     import logging
#     from django_auth_ldap.config import LDAPSearch, GroupOfUniqueNamesType

#     AUTH_LDAP_SERVER_URI = str(env('LDAP_SERVER'))
#     AUTH_LDAP_BIND_DN = str(env('LDAP_BIND_DN'))
#     AUTH_LDAP_BIND_PASSWORD = str(env('LDAP_BIND_PASSWORD'))

#     ldap_self_signed_cert = bool(env('LDAP_SELF_SIGNED_CERT')) or False
#     if ldap_self_signed_cert:
#         # Ignore certificate errors to accept a self-signed cert.
#         LDAP_IGNORE_CERT_ERRORS = True
#         AUTH_LDAP_GLOBAL_OPTIONS = {
#             ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER
#         }

#     AUTH_LDAP_USER_SEARCH = LDAPSearch(
#         str(env('LDAP_USER_SEARCH_BASE_DN')),
#         ldap.SCOPE_SUBTREE,
#         str(env('LDAP_USER_SEARCH_FILTER')),
#     )

#     AUTH_LDAP_USER_ATTR_MAP = {
#         'first_name': 'givenName',
#         'last_name': 'sn',
#         'email': 'mail',
#         'name': 'displayName',
#     }

#     AUTH_LDAP_GROUP_TYPE = GroupOfUniqueNamesType()

#     AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
#         str(env('LDAP_GROUP_SEARCH_BASE_DN')),
#         ldap.SCOPE_SUBTREE,
#         str(env('LDAP_GROUP_SEARCH_FILTER')),
#     )

#     AUTH_LDAP_REQUIRE_GROUP = None
#     AUTH_LDAP_DENY_GROUP = None

#     AUTH_LDAP_FIND_GROUP_PERMS = True
#     AUTH_LDAP_CACHE_GROUPS = False
#     AUTH_LDAP_GROUP_CACHE_TIMEOUT = 3600

#     AUTH_LDAP_DEFAULT_EMAIL_DOMAIN = str(env('LDAP_DEFAULT_EMAIL_DOMAIN'))
#     AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION = str(env(
#         'LDAP_DEFAULT_SENTRY_ORGANIZATION'))
#     AUTH_LDAP_SENTRY_ORGANIZATION_ROLE_TYPE = str(env(
#         'LDAP_SENTRY_ORGANIZATION_ROLE_TYPE'))

#     group_role_mapping = env('LDAP_SENTRY_GROUP_ROLE_MAPPING_OWNER') or env('LDAP_SENTRY_GROUP_ROLE_MAPPING_MANAGER') or env(
#         'LDAP_SENTRY_GROUP_ROLE_MAPPING_ADMIN') or env('LDAP_SENTRY_GROUP_ROLE_MAPPING_MEMBER') or False
#     if group_role_mapping:
#         AUTH_LDAP_SENTRY_GROUP_ROLE_MAPPING = {
#             'owner': env('LDAP_SENTRY_GROUP_ROLE_MAPPING_OWNER'),
#             'manager': env('LDAP_SENTRY_GROUP_ROLE_MAPPING_MANAGER'),
#             'admin': env('LDAP_SENTRY_GROUP_ROLE_MAPPING_ADMIN'),
#             'member': env('LDAP_SENTRY_GROUP_ROLE_MAPPING_MEMBER'),
#         }

#     AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS = True
#     AUTH_LDAP_SENTRY_SUBSCRIBE_BY_DEFAULT = True
#     AUTH_LDAP_SENTRY_USERNAME_FIELD = 'sAMAccountName'

#     SENTRY_MANAGED_USER_FIELDS = (
#         'email', 'first_name', 'last_name', 'password', )

#     AUTHENTICATION_BACKENDS = AUTHENTICATION_BACKENDS + (
#         'sentry_ldap_auth.backend.SentryLdapBackend',
#     )

#     ldap_debug = env('LDAP_DEBUG') or False
#     if ldap_debug:
#         logger = logging.getLogger('django_auth_ldap')
#         logger.addHandler(logging.StreamHandler())
#         logger.addHandler(logging.FileHandler('/tmp/ldap2.log'))
#         logger.setLevel('DEBUG')

#         LOGGING['overridable'] = ['sentry', 'django_auth_ldap']
#         LOGGING['loggers']['django_auth_ldap'] = {
#             'handlers': ['console'],
#             'level': 'DEBUG'
#         }
