/*
** external.cpp
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


#include "quazaaglobals.h"
#include "quazaasettings.h"

#include "externals.h"
#include "winmain.h"

using namespace Security;

void Security::postLogMessage(LogSeverity eSeverity, QString sMessage, bool bDebug)
{
	switch ( eSeverity )
	{
	case LogSeverity::Warning:
		sMessage = QObject::tr ( "Warning: " ) + sMessage;
		break;

	case LogSeverity::Error:
		sMessage = QObject::tr ( "Error: " ) + sMessage;
		break;

	case LogSeverity::Critical:
		sMessage = QObject::tr ( "Critical Error: " ) + sMessage;
		break;

	default:
		break; // do nothing
	}

	if ( bDebug )
	{
		sMessage = systemLog.msgFromComponent( Component::Security ) + sMessage;
		qDebug() << sMessage.toLocal8Bit().constData();
	}
	else
	{
		systemLog.postLog( eSeverity, Component::Security, sMessage );
	}
}

QString Security::dataPath()
{
	return QuazaaGlobals::DATA_PATH();
}

Security::SecuritySettings securitySettigs;

void Security::SecuritySettings::start()
{
	connect( &quazaaSettings, SIGNAL( securitySettingsChanged() ),
			 &securitySettigs, SLOT( settingsChanged() ), Qt::QueuedConnection );

#ifndef QUAZAA_SETUP_UNIT_TESTS
	// Make sure securityManager is informed about application shutdown.
	connect( MainWindow, SIGNAL( shutDown() ), &securityManager, SLOT( shutDown() ) );
#endif

	settingsChanged();
}

void Security::SecuritySettings::stop()
{
	disconnect( &quazaaSettings, SIGNAL( securitySettingsChanged() ),
				&securitySettigs, SLOT( settingsChanged() ) );
}

/**
 * @brief Settings::settingsChanged needs to be triggered on setting changes.
 * Qt slot. Pulls all relevant settings from quazaaSettings.Security
 * and forwards them to the security manager.
 * Locking: YES
 */
void Security::SecuritySettings::settingsChanged()
{
	m_oLock.lock();

	m_bLogIPCheckHits     = quazaaSettings.Security.LogIPCheckHits;
	m_bIgnorePrivateIPs   = quazaaSettings.Security.IgnorePrivateIP;
	m_tRuleExpiryInterval = quazaaSettings.Security.RuleExpiryInterval * 1000;

	m_oLock.unlock();

	emit settingsUpdate();
}
