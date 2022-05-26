import asyncio
import logging

from millegrilles.docker.ParseConfiguration import ConfigurationService


logger = logging.getLogger(__name__)

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'


PARAMS_SERVICE_2 = {
    'HOSTNAME': 'mon_hostname_remplace',
    'IDMG': 'zabcd1234',
    '__nom_application': 'dummy_app',
    '__certificat_info': {
        'label_prefix': 'pki.mq',
    },
    '__secrets': {'pki.mq.key.20220525233951': 'd50cl4w5ejvld3uygx21uau6o', 'passwd.mqadmin.20220526132352': 'zsh04jo3za5syw5qfk446l527'},
    '__configs': {'instance.securite': '1vzbldqgo19vgfp1tkyyl56xs', 'pki.mq.cert.20220525233951': '330mn73z2adttl9f7akqewdkj', 'instance.idmg': 'miyf3jifho0b4isic8xgzceah', 'instance.id': 'o6jswncu6d993pa71p1arcc84', 'pki.millegrille': 'x67clk6zp9rjezcn3psttw539'},
    '__docker_config_datee': {
        'pki.mq': {
          '20220525233951': {
            'key': {
              'name': 'pki.mq.key.20220525233951',
              'id': 'd50cl4w5ejvld3uygx21uau6o'
            },
            'cert': {
              'name': 'pki.mq.cert.20220525233951',
              'id': '330mn73z2adttl9f7akqewdkj'
            }
          },
          'current': {
            'key': {
              'name': 'pki.mq.key.20220525233951',
              'id': 'd50cl4w5ejvld3uygx21uau6o'
            },
            'cert': {
              'name': 'pki.mq.cert.20220525233951',
              'id': '330mn73z2adttl9f7akqewdkj'
            }
          }
        },
        'passwd.mqadmin': {
          '20220526132352': {
            'password': {
              'name': 'passwd.mqadmin.20220526132352',
              'id': 'zsh04jo3za5syw5qfk446l527'
            }
          },
          'current': {
            'password': {
              'name': 'passwd.mqadmin.20220526132352',
              'id': 'zsh04jo3za5syw5qfk446l527'
            }
          }
        }
      }
}

CONFIG_SERVICE_2 = {
  "name": "mq",
  "image": "docker.maceroc.com/mg_rabbitmq:3.9-management_1",
  "env": {
    "MG_KEY": "/run/secrets/key.pem",
    "WEB_KEY": "/run/secrets/webkey.pem",
    "CONFIG_FILE": "/opt/rabbitmq/dist/config/rabbitmq_ipv6management.config",
    "NODENAME": "rabbit@mq",
    "TEST_VAL": "${HOSTNAME}"
  },
  "mounts": [{"source": "rabbitmq-data", "target":  "/var/lib/rabbitmq", "type": "volume"}],
  "constraints": ["node.labels.millegrilles.mq == true"],
  "configs": [
    {
      "name": "pki.millegrille",
      "filename": "/opt/rabbitmq/dist/certs/calist.cert.pem"
    },
    {
      "certificate": True,
      "filename": "/opt/rabbitmq/dist/certs/cert.pem"
    },
    {
      "certificate": True,
      "filename": "/opt/rabbitmq/dist/certs/webcert.pem"
    }
  ],
  "secrets": [
    {
      "key": True,
      "filename": "key.pem"
    },
    {
      "key": True,
      "filename": "webkey.pem"
    }
  ],
  "endpoint_spec": {
    "mode": "vip",
    "ports": [
      {
        "published_port": 8443,
        "target_port": 8443,
        "protocol": "tcp"
      },{
        "published_port": 5673,
        "target_port": 5673,
        "protocol": "tcp"
      }
    ]
  },
  "networks": [{
    "target": "millegrille_net",
    "aliases": ["mq"]
  }],
  "labels": {
    "millegrille": "${IDMG}"
  },
  "resources": {
    "cpu_limit": 2000000000,
    "mem_limit": 629145600
  },
  "mode": {
    "mode": "replicated",
    "replicas": 1
  }
}


def test_config_service_minimal():
    config_dict = {"name": "test_service1", "image": "docker.maceroc.com/test1"}
    config_service = ConfigurationService(config_dict)
    config_service.parse()
    config_parsed = config_service.generer_docker_config()
    logger.debug("Configuration docker parsed : %s" % config_parsed)


def test_config_service_complet():
    config_service = ConfigurationService(CONFIG_SERVICE_2, PARAMS_SERVICE_2)
    config_service.parse()
    config_parsed = config_service.generer_docker_config()
    logger.debug("Configuration docker parsed : %s" % config_parsed)


def main():
    logger.info("Debut main()")
    test_config_service_minimal()
    test_config_service_complet()


if __name__ == '__main__':
    # logging.basicConfig()
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARN)
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    main()
