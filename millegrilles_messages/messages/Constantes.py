
# Logging
LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'

# Kinds de messages
KIND_DOCUMENT = 0
KIND_REQUETE = 1
KIND_COMMANDE = 2
KIND_TRANSACTION = 3
KIND_REPONSE = 4
KIND_EVENEMENT = 5
KIND_REPONSE_CHIFFREE = 6
KIND_TRANSACTION_MIGREE = 7
KIND_COMMANDE_INTER_MILLEGRILLE = 8

# Env params
ENV_MQ_HOSTNAME = 'MQ_HOSTNAME'
ENV_MQ_PORT = 'MQ_PORT'
ENV_MQ_CONNECTION_ATTEMPTS = 'MQ_CONNECTION_ATTEMPTS'
ENV_MQ_RETRY_DELAY = 'MQ_RETRY_DELAY'
ENV_MQ_HEARTBEAT = 'MQ_HEARTBEAT'
ENV_MQ_BLOCKED_CONNECTION_TIMEOUT = 'MQ_BLOCKED_CONNECTION_TIMEOUT'
ENV_URL_CONSIGNATION = 'URL_CONSIGNATION'
ENV_PATH_EXTRACTION = 'PATH_EXTRACTION'
ENV_SOLR_URL = 'SOLR_URL'
ENV_DIR_STAGING = 'DIR_STAGING'

ENV_REDIS_HOSTNAME = 'REDIS_HOSTNAME'
ENV_REDIS_PORT = 'REDIS_PORT'
ENV_REDIS_USERNAME = 'REDIS_USERNAME'
ENV_REDIS_PASSWORD = 'REDIS_PASSWORD'
ENV_REDIS_PASSWORD_PATH = 'REDIS_PASSWORD_PATH'

ENV_CA_PEM = 'CA_PEM'
ENV_CERT_PEM = 'CERT_PEM'
ENV_KEY_PEM = 'KEY_PEM'
ENV_CONFIG_SENSEURSPASSIFS = 'CONFIG_SENSEURSPASSIFS'
ENV_CERT_APPAREIL_PEM = 'CERT_APPAREIL_PEM'
ENV_KEY_APPAREIL_PEM = 'KEY_APPAREIL_PEM'

ENV_WEB_PORT = 'WEB_PORT'

SECURITE_PUBLIC = '1.public'
SECURITE_PRIVE = '2.prive'
SECURITE_PROTEGE = '3.protege'
SECURITE_SECURE = '4.secure'


DELEGATION_GLOBALE_PROPRIETAIRE = 'proprietaire'


ROLE_CORE = 'core'
ROLE_BACKUP = 'backup'


DOMAINE_INSTANCE = 'instance'
DOMAINE_CORE_CATALOGUES = 'CoreCatalogues'
DOMAINE_CORE_PKI = 'CorePki'
DOMAINE_CORE_TOPOLOGIE = 'CoreTopologie'
DOMAINE_CORE_MAITREDESCOMPTES = 'CoreMaitreDesComptes'
DOMAINE_FICHIERS = 'fichiers'
DOMAINE_BACKUP = 'backup'

# Champs messages
# MESSAGE_ENTETE='en-tete'
MESSAGE_FINGERPRINT_CERTIFICAT = 'fingerprint_certificat'
MESSAGE_ID = 'id'
MESSAGE_SIGNATURE = 'sig'
MESSAGE_PUBKEY = 'pubkey'
MESSAGE_VERSION_1 = 1
MESSAGE_IDMG = 'idmg'
MESSAGE_UUID_TRANSACTION = 'uuid_transaction'
MESSAGE_ESTAMPILLE = 'estampille'
MESSAGE_VERSION = 'version'
MESSAGE_DOMAINE = 'domaine'
MESSAGE_ACTION = 'action'
MESSAGE_PARTITION = 'partition'
MESSAGE_CERTIFICAT = 'certificat'
MESSAGE_HACHAGE = MESSAGE_ID
MESSAGE_CERTIFICAT_INCLUS = 'certificat'


REQUETE_CORETOPOLOGIE_LISTE_DOMAINES = 'listeDomaines'
REQUETE_GLOBAL_NOMBRE_TRANSACTIONS = 'getNombreTransactions'
