#!/bin/bash

pip3 install --no-cache-dir -r requirements.txt

python3 ./setup.py install

# Configuration groups/users pour millegrilles
cd $BUNDLE_FOLDER
rm -rf $BUILD_FOLDER
