#!/usr/bin/env sh
set -e

create_group() {
	if ! getent group pf-dashboard >/dev/null 2>&1; then
		if command -v groupadd >/dev/null 2>&1; then
			groupadd --system pf-dashboard
		elif command -v addgroup >/dev/null 2>&1; then
			addgroup --system pf-dashboard
		fi
	fi
}

create_user() {
	if ! getent passwd pf-dashboard >/dev/null 2>&1; then
		if command -v useradd >/dev/null 2>&1; then
			useradd --system --home-dir /var/lib/pf-dashboard --shell /usr/sbin/nologin --gid pf-dashboard pf-dashboard
		elif command -v adduser >/dev/null 2>&1; then
			adduser --system --home /var/lib/pf-dashboard --shell /usr/sbin/nologin --ingroup pf-dashboard pf-dashboard
		fi
	fi
}

create_group
create_user

if [ -d /var/lib ]; then
	install -d -m 0750 -o pf-dashboard -g pf-dashboard /var/lib/pf-dashboard
fi
