#!/bin/bash
# Bastion Curfew — shuts down the system during restricted hours
# Runs every 2 minutes via cron during 21:30–04:59
/usr/sbin/shutdown -h now "Bastion curfew: system shutting down"
