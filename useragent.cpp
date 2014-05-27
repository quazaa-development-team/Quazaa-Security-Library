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

#include <QDebug>
#include <QRegularExpression>

#include "useragent.h"

UserAgent::UserAgent( const QString& sUserAgent ) :
	m_sUserAgent( sUserAgent.trimmed() )
{
	// TODO: improve parsing to reduce the number of regular expression usages

	qDebug() << "UserAgent: " << sUserAgent.toLocal8Bit().data();

	const QString d = "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])";  // matches range 0-255
	const QString sDefaultVersion = d + "\\." + d + "\\." + d + "\\." + d;   // matches d.d.d.d
	const QString sAgent = ".*\\s" + sDefaultVersion;
	const QString sAgentLibrary = sAgent + "\\s\\(" + sAgent + "\\)";
	const QString sSimple = d + "\\." + d;
	const QString sEMuleVersion  = sSimple + "[a-z]";

	if ( QRegularExpression( "\\A" + sAgentLibrary + "\\z" ).match( sUserAgent ).hasMatch() )
	{
		m_eStyle = Style::GnucDNA;

		qDebug() << "Seems to be GnucDNA style.";

		int nPos      = sUserAgent.lastIndexOf( '(' );
		parse( sUserAgent.left( nPos ),
			   Style::QuazaaDefault, m_sClientName,  m_oClientVersion  );

		parse( sUserAgent.mid( nPos + 1, sUserAgent.size() - nPos - 2 ),
			   Style::QuazaaDefault, m_sLibraryName, m_oLibraryVersion );
	}
	else if ( QRegularExpression( "\\A" + sAgent ).match( sUserAgent ).hasMatch() )
	{
		m_eStyle = Style::QuazaaDefault;
		qDebug() << "Seems to be Default style.";
		parse( sUserAgent, Style::QuazaaDefault, m_sClientName,  m_oClientVersion  );
	}
	else if ( QRegularExpression( "\\A.*\\s" + sEMuleVersion ).match( sUserAgent ).hasMatch() )
	{
		m_eStyle = Style::eMule;
		qDebug() << "Seems to be eMule style.";
		parse( sUserAgent, Style::eMule, m_sClientName,  m_oClientVersion  );
	}
	else if ( QRegularExpression( "\\A.*\\s" + sSimple ).match( sUserAgent ).hasMatch() )
	{
		m_eStyle = Style::Simple;
		qDebug() << "Seems to be Simple style.";
		parse( sUserAgent, Style::Simple, m_sClientName,  m_oClientVersion  );
	}
	else
	{
		m_eStyle = Style::Unknown;
		qDebug() << "Unknown style.";
		m_sClientName = sUserAgent.trimmed();
	}
}

bool UserAgent::operator<( const UserAgent& other )
{
	return m_oClientVersion < other.m_oClientVersion;
}

bool UserAgent::operator>( const UserAgent& other )
{
	return m_oClientVersion > other.m_oClientVersion;
}

bool UserAgent::operator<=( const UserAgent& other )
{
	return m_oClientVersion <= other.m_oClientVersion;
}

bool UserAgent::operator>=( const UserAgent& other )
{
	return m_oClientVersion >= other.m_oClientVersion;
}

bool UserAgent::operator==(const UserAgent& other)
{
	return m_sClientName.compare( other.m_sUserAgent, Qt::CaseInsensitive ) == 0 &&
		   ( !m_oClientVersion.version() || !other.m_oClientVersion.version() ||
			  m_oClientVersion.version() ==  other.m_oClientVersion.version() );
}

bool UserAgent::operator!=(const UserAgent& other)
{
	return !operator==( other );
}

void UserAgent::parse( const QString& sWhat, const UserAgent::Style eHow,
					   QString& sNameDest, ClientVersion& rClientDest )
{
	const QString d = "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])";  // matches range 0-255
	const QString sDefaultVersion = d + "\\." + d + "\\." + d + "\\." + d;   // matches d.d.d.d

	const QString sSimple = d + "\\." + d;
	const QString sEMuleVersion  = sSimple + "[a-z]";

	switch ( eHow )
	{
	case Style::QuazaaDefault:
	{
		int nPos    = sWhat.lastIndexOf( QRegularExpression( sDefaultVersion ) );
		sNameDest   = sWhat.left( nPos ).trimmed();
		rClientDest = ClientVersion( sWhat.mid( nPos ), ClientVersion::Style::QuazaaDefault );
		break;
	}

	case Style::eMule:
	{
		int nPos    = sWhat.lastIndexOf( QRegularExpression( sEMuleVersion ) );
		sNameDest   = sWhat.left( nPos ).trimmed();
		rClientDest = ClientVersion( sWhat.mid( nPos ), ClientVersion::Style::eMule );
		break;
	}

	case Style::Simple:
	{
		int nPos    = sWhat.lastIndexOf( QRegularExpression( sSimple ) );
		sNameDest   = sWhat.left( nPos ).trimmed();
		rClientDest = ClientVersion( sWhat.mid( nPos ), ClientVersion::Style::Simple );
		break;
	}

	default:
		// do nothing
		break;
	}
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
