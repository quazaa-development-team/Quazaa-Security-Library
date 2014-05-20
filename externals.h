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

#include <QString>

namespace Security
{
/**
 * @brief The CountryHasher struct allows to transform a two letter country code into its unique 32
 * bit hash.
 */
struct CountryHasher
{
	/**
	 * @brief operator() transforms a given country code into its hash.
	 * @param sCountryCode  The two letter country code.
	 * @return The 32 bit hash of the country code.
	 */
	quint32 operator()( const QString& sCountryCode )
	{
		Q_ASSERT( sCountryCode.length() == 2 );

		quint32 nReturn = 1;
		nReturn *= sCountryCode[0].unicode();
		nReturn *= sCountryCode[1].unicode();
		return nReturn;
	}
};

/**
 * @brief postLogMessage writes a message to the system log or to the debug output.
 * <br><b>Locking: /</b>
 *
 * @param eSeverity  The message severity.
 * @param sMessage   The message string.
 * @param bDebug     If set to <code>true</code>, the message is send to qDebug() instead of to the
 * system log. Defaults to <code>false</code>.
 */
void postLogMessage( LogSeverity eSeverity, QString sMessage, bool bDebug = false );

/**
 * @brief dataPath allows the Manager to access the data path.
 * <br><b>Locking: /</b>
 *
 * @return The location where the Manager is supposed to store its data between sessions.
 */
QString dataPath();

class SecuritySettings : public QObject
{
	Q_OBJECT

private:
	QMutex  m_oLock;

	bool    m_bLogIPCheckHits;
	bool    m_bIgnorePrivateIPs;
	quint64 m_tRuleExpiryInterval;

public:
	/**
	 * @brief start must be called on application startup. Inintalizes the necessary signal/slot
	 * connections and makes sure the resective settings are loaded from the settings manager.
	 */
	void start();

	/**
	 * @brief stop should be called on application shutdown.
	 */
	void stop();

	/**
	 * @brief logIPCheckHits allows to access the logIPCheckHits setting.
	 * <br><b>Locking: YES</b>
	 *
	 * @return <code>true</code> if the Manager should report IP rule hits to the system log;
	 * <br><code>false</code> otherwise
	 */
	bool logIPCheckHits();

	/**
	 * @brief logIPCheckHits allows to access the ignorePrivateIPs setting.
	 * <br><b>Locking: YES</b>
	 *
	 * @return <code>true</code> if the Manager should deny private IPs on principle;
	 * <br><code>false</code> otherwise
	 */
	bool ignorePrivateIPs();

	/**
	 * @brief logIPCheckHits allows to access the ruleExpiryInterval setting.
	 * <br><b>Locking: YES</b>
	 *
	 * @return the time in ms between two rule expiry cleanups.
	 */
	quint64 ruleExpiryInterval();

public slots:
	/**
	 * @brief settingsChanged pulls all relevant settings from the settings manager and notifies the
	 * security Manager.
	 * <br><b>Locking: YES</b>
	 *
	 * Note: Needs to be triggered on setting changes.
	 */
	void settingsChanged();

signals:
	/**
	 * @brief settingsUpdate informs the Manager about changed settings having been pulled from the
	 * settings manager.
	 */
	void settingsUpdate();
};
}

extern Security::SecuritySettings securitySettings;

#endif // EXTERNALS_H
