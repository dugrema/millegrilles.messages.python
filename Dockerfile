FROM python:3.12 as stage1

ENV BUILD_FOLDER=/opt/millegrilles/build \
    BUNDLE_FOLDER=/opt/millegrilles/dist \
    PYTHONPATH=/opt/millegrilles/dist \
    SRC_FOLDER=/opt/millegrilles/build/src

WORKDIR /opt/millegrilles/build

COPY requirements.txt $BUILD_FOLDER/requirements.txt
COPY ./fixes/oscrypto_130_fix_d5f3437ed24257895ae1edd9e503cfb352e635a8.zip $BUILD_FOLDER/oscrypto_130_fix_d5f3437ed24257895ae1edd9e503cfb352e635a8.zip

RUN pip3 install setuptools && \
    pip3 install --no-cache-dir -r $BUILD_FOLDER/requirements.txt && \
    pip3 install --force-reinstall ./fixes/oscrypto_130_fix_d5f3437ed24257895ae1edd9e503cfb352e635a8.zip

# Note : bug oscrypto
# https://community.snowflake.com/s/article/Python-Connector-fails-to-connect-with-LibraryNotFoundError-Error-detecting-the-version-of-libcrypto
# retirer install force oscrypto a partir de la version apres oscrypto 1.3.0

# Pour offline build
#ENV PIP_FIND_LINKS=$BUILD_FOLDER/pip \
#    PIP_RETRIES=0 \
#    PIP_NO_INDEX=true
# Note: faire rm -r $BUILD_FOLDER/pip a la fin du RUN

FROM stage1

COPY . $BUILD_FOLDER
RUN python3 ./setup.py install

WORKDIR /opt/millegrilles/dist

ARG VBUILD=2024.0.0
ENTRYPOINT ["python3"]
