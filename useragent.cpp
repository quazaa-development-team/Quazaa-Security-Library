/*
** useragent.cpp
**
** Copyright © Quazaa Development Team, 2014.
** This file is part of QUAZAA (quazaa.sourceforge.net)
**
** Quazaa is free software; this file may be used under the terms of the GNU
** General Public License version 3.0 or later as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.
**
** Quazaa is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** Please review the following information to ensure the GNU General Public
** License version 3.0 requirements will be met:
** http://www.gnu.org/copyleft/gpl.html.
**
** You should have received a copy of the GNU General Public License version
** 3.0 along with Quazaa; if not, write to the Free Software Foundation,
** Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <QRegularExpression>

#include "useragent.h"

UserAgent::UserAgent( const QString& sUserAgent ) :
	m_sUserAgent( sUserAgent )
{
	// TODO: parse input
}

QString UserAgent::userAgentString() const
{
	return m_sUserAgent;
}

QString UserAgent::clientName() const
{
	return m_sClientName;
}

ClientVersion UserAgent::clientVersion() const
{
	return m_oClientVersion;
}

QString UserAgent::libraryName() const
{
	return m_sLibraryName;
}

ClientVersion UserAgent::libraryVersion() const
{
	return m_oLibraryVersion;
}
