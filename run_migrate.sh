#! /bin/bash

if [[ "${DATABASE_TYPE:-}" == postgres* ]]
then
    LOCAL_DATABASE_TYPE="postgres"
    LOCAL_DATABASE_PORT="${DATABASE_PORT:-5432}"
elif [[ "${DATABASE_TYPE:-}" == mysql* || "${DATABASE_TYPE:-}" == mariadb* ]]
then
    LOCAL_DATABASE_TYPE="mysql"
    LOCAL_DATABASE_PORT="${DATABASE_PORT:-3306}"
fi

if [ -z "${DATABASE_HOSTNAME:-}" ] && [ -n "${DATABASE_URL:-}" ]
then
    if [[ $DATABASE_URL =~ @([^:/]+) ]]
    then
        LOCAL_DATABASE_HOSTNAME="${BASH_REMATCH[1]}"
    fi

    LOCAL_DATABASE_PORT=""
    LOCAL_DATABASE_TYPE=""

    # Check for PostgreSQL
    if [[ $DATABASE_URL == postgres* ]]; then
        LOCAL_DATABASE_TYPE="postgres"
        # Try to match a port number after the hostname
        if [[ $DATABASE_URL =~ @[^:/]+:([0-9]+) ]]; then
            LOCAL_DATABASE_PORT="${BASH_REMATCH[1]}"
        else
            LOCAL_DATABASE_PORT="5432" # The default PostgreSQL port
        fi

    # Check for MySQL or MariaDB
    elif [[ $DATABASE_URL == mysql* || $DATABASE_URL == mariadb* ]]; then
        LOCAL_DATABASE_TYPE="mysql"
        # Try to match a port number after the hostname
        if [[ $DATABASE_URL =~ @[^:/]+:([0-9]+) ]]; then
            LOCAL_DATABASE_PORT="${BASH_REMATCH[1]}"
        else
            LOCAL_DATABASE_PORT="3306" # The default MySQL/MariaDB port
        fi

    else
        echo "Unknown database type."

    fi
elif [ -n "${DATABASE_HOSTNAME:-}" ]
then
    LOCAL_DATABASE_HOSTNAME="${DATABASE_HOSTNAME:-}"
fi

if [ -n "${LOCAL_DATABASE_TYPE:-}" ]
then
    echo "=== Waiting for the database to become available ==="
    while ! nc -w 1 -z "$LOCAL_DATABASE_HOSTNAME" "$LOCAL_DATABASE_PORT"
    do
        sleep 0.1
    done
    echo "                        DONE                        "
fi
FLASK_APP=app
flask db upgrade