PORTNAME=	pf-dashboard
DISTVERSION=	0.1.0
CATEGORIES=	security

MAINTAINER=	you@example.com
COMMENT=	Web dashboard for PF and firewall diagnostics
WWW=	https://github.com/REPLACE_ME/REPLACE_ME

# TODO: set LICENSE after adding a project license file in upstream repo.

USES=		go:modules
USE_RC_SUBR=	pf_dashboard

USE_GITHUB=	yes
GH_ACCOUNT=	REPLACE_ME
GH_PROJECT=	REPLACE_ME

GO_TARGET=	.
PLIST_FILES=	bin/pf-dashboard

post-install:
	${INSTALL_PROGRAM} ${WRKDIR}/bin/pf-dashboard ${STAGEDIR}${PREFIX}/bin/pf-dashboard

.include <bsd.port.mk>
