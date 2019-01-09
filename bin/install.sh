#!/usr/bin/env bash

TARGET_DIR=/usr/local/share/lua/5.1/kong/plugins

PLUGIN_NAME=sign-verify

PLUGINS_PATH=$(cd "$(dirname "$0")/../kong/plugins/";pwd)

cd ${TARGET_DIR}

rm -fr ${PLUGIN_NAME}

mkdir ${PLUGIN_NAME}

cp -R ${PLUGINS_PATH}/${PLUGIN_NAME}/* ./${PLUGIN_NAME}/