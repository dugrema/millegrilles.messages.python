FROM python:3.10

ENV BUILD_FOLDER=/opt/millegrilles/build \
    BUNDLE_FOLDER=/opt/millegrilles/dist \
    PYTHONPATH=/opt/millegrilles/dist \
    SRC_FOLDER=/opt/millegrilles/build/src

COPY . $BUILD_FOLDER

WORKDIR /opt/millegrilles/build
ENTRYPOINT ["python3"]

RUN pip3 install --no-cache-dir -r $BUILD_FOLDER/requirements.txt && \
    python3 ./setup.py install && \
    pip3 install --force-reinstall https://github.com/wbond/oscrypto/archive/d5f3437ed24257895ae1edd9e503cfb352e635a8.zip

# Note : bug oscrypto
# https://community.snowflake.com/s/article/Python-Connector-fails-to-connect-with-LibraryNotFoundError-Error-detecting-the-version-of-libcrypto
# retirer install force oscrypto a partir de la version apres oscrypto 1.3.0

WORKDIR /opt/millegrilles/dist
