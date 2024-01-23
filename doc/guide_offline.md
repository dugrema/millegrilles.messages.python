# Offline

## Image docker
cp -rl /var/lib/pip .
cp -r /backup/.../pip/fixes ./pip_fixes

Commande RUN de Dockerfile

Ajouter ENV suivant:

ENV PIP_FIND_LINKS=$BUILD_FOLDER/pip \
    PIP_RETRIES=0 \
    PIP_NO_INDEX=true
