#!/bin/bash

# Generer version.txt
. ./image_info.txt

sed -i "/\\_VERSION__ =/c\\__VERSION__ = \"${VERSION}\"" setup.py

python3 setup.py sdist
python3 setup.py bdist_wheel
