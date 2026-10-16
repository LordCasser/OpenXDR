#!/bin/sh
set -eu
chmod 700 /var/lib/postgresql/data
exec patroni /etc/patroni/patroni.yml
