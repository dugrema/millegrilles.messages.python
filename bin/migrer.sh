#!/bin/bash

# Note : add groups millegrilles, mgsecrets

. /var/opt/millegrilles/venv/bin/activate

PYTHONPATH=/var/opt/millegrilles/python
export CERT_PEM=/var/opt/millegrilles/secrets/pki.instance.cert
export KEY_PEM=/var/opt/millegrilles/secrets/pki.instance.key
export CA_PEM=/var/opt/millegrilles/configuration/pki.millegrille.cert
export MQ_HOSTNAME=localhost

python3 -m millegrilles_messages.backup \
  migrer \
  --cleca /home/mathieu/cles/cle.json \
  --cledestca /home/mathieu/cles/cle.json \
  --source /home/mathieu/migration/transactions \
  --domaine $1
