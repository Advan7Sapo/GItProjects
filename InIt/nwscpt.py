#!/bin/bash
header="#!/usr/bin/env python3
#----------------------------------------------------------------------------
# Project	: $1
#----------------------------------------------------------------------------
# Date		: $data
#----------------------------------------------------------------------------
# WheremI	: $whrmi
#----------------------------------------------------------------------------
# CreatedBy	: ADVAN7 Offensive Security | https://github.com/Advan7Sapo
#----------------------------------------------------------------------------
"
clear
echo "$header" > $1
chmod 755 $1
gedit $1

