/*
** external.h
**
** Copyright © Quazaa Development Team, 2009-2014.
** This file is part of the Quazaa Security Library (quazaa.sourceforge.net)
**
** The Quazaa Security Library is free software; this file may be used under the terms of the GNU
** General Public License version 3.0 or later as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.
**
** The Quazaa Security Library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** Please review the following information to ensure the GNU General Public
** License version 3.0 requirements will be met:
** http://www.gnu.org/copyleft/gpl.html.
**
** You should have received a copy of the GNU General Public License version
** 3.0 along with the Quazaa Security Library; if not, write to the Free Software Foundation,
** Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef EXTERNALS_H
#define EXTERNALS_H

// the minimal amount of IP related rules before enabling the miss cache
#define SECURITY_MIN_RULES_TO_ENABLE_CACHE 30

#define SECURITY_LOG_BAN_SOURCES 0
#define SECURITY_DISABLE_IS_PRIVATE_OLD 0

// Enable/disable GeoIP support of the security library.
#define SECURITY_ENABLE_GEOIP 1

#if SECURITY_ENABLE_GEOIP
#include "geoiplist.h"
#endif

#include "NetworkCore/queryhit.h"
#include "NetworkCore/Hashes/hashset.h"

#include "commonfunctions.h"

#include "Misc/idprovider.h"
#include "Misc/timedsignalqueue.h"

namespace Security
{

/**
 * @brief postLogMessage writes a message to the system log or to the debug output.
 * Requires locking: /
 * @param eSeverity : the message severity
 * @param sMessage : the message string
 * @param bDebug : Defaults to false. If set to true, the message is send to qDebug() instead of
 * to the system log.
 */
void postLogMessage( LogSeverity eSeverity, QString sMessage, bool bDebug = false );

/**
 * @brief dataPath
 * @return
 */
QString dataPath();

class SecuritySettings : public QObject
{
	Q_OBJECT

public:
	QMutex  m_oLock;

	bool    m_bLogIPCheckHits;
	bool    m_bIgnorePrivateIPs;
	quint64 m_tRuleExpiryInterval;

	void start();
	void stop();

public slots:
	/**
	 * @brief Settings::settingsChanged needs to be triggered on setting changes.
	 * Qt slot. Pulls all relevant settings from quazaaSettings.Security
	 * and forwards them to the security manager.
	 * Locking: YES
	 */
	void settingsChanged();

signals:
	void settingsUpdate();
};
}

extern Security::SecuritySettings securitySettings;

#endif // EXTERNALS_H
