/*
** external.h
**
** Copyright © Quazaa Development Team, 2009-2013.
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

// Enable/disable GeoIP support of the security library.
#define SECURITY_ENABLE_GEOIP 1

#if SECURITY_ENABLE_GEOIP
#include "geoiplist.h"
#endif

#include "NetworkCore/Hashes/hash.h"
#include "NetworkCore/queryhit.h"

#include "commonfunctions.h"

#include "quazaaglobals.h"
#include "quazaasettings.h"

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
void postLogMessage(LogSeverity::Severity eSeverity, QString sMessage, bool bDebug);

/**
 * @brief dataPath
 * @return
 */
QString dataPath();
// TODO: manage security settings updates see Manager::start()
}
