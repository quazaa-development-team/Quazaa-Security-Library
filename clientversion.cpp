/*
** clientversion.cpp
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

#include "clientversion.h"

ClientVersion::ClientVersion() :
	m_eStyle( Style::Unknown ),
	m_nVersion( 0 ),
	m_sVersion( "" )
{
}

ClientVersion::ClientVersion( const QString& sVersion , Style eStyle ) :
	m_eStyle( eStyle )
{
	qDebug() << "Parsing ClientVersion String: " << sVersion.toLocal8Bit().data();

	quint8 bytes[4];

	bytes[0] = 0;
	bytes[1] = 0;
	bytes[2] = 0;
	bytes[3] = 0;

	QString sTmp = sVersion.trimmed();
	int nVersionLength = 0;

	switch ( eStyle )
	{
	case Style::QuazaaDefault:
	{
		int n, nPos;
		for ( quint8 i = 3; i > 0; --i )
		{
			nPos = sTmp.indexOf( '.' );
			bytes[i] = sTmp.left( nPos ).toUInt();
			sTmp = sTmp.mid( nPos + 1 );
		}

		if ( sTmp.indexOf( QRegularExpression( "(1[0-9][0-9]|2[0-4][0-9]|25[0-5])" ) ) == 0 )
		{
			n = 3;
		}
		else if ( sTmp.indexOf( QRegularExpression( "[1-9][0-9]" ) ) == 0 )
		{
			n = 2;
		}
		else
		{
#ifdef _DEBUG
			Q_ASSERT( sTmp.indexOf( QRegularExpression( "[0-9]" ) ) == 0 );
#endif // _DEBUG
			n = 1;
		}

		bytes[0] = sTmp.left( n ).toUInt();

		nVersionLength = sVersion.size() - sTmp.size() + n;

		break;
	}
	case Style::eMule:
	case Style::Simple:
	{
		int nPos = sTmp.indexOf( '.' );
		bytes[3] = sTmp.left( nPos ).toUInt();
		sTmp     = sTmp.mid( nPos + 1 );

		int n;
		if ( sTmp.indexOf( QRegularExpression( "(1[0-9][0-9]|2[0-4][0-9]|25[0-5])" ) ) == 0 )
		{
			n = 3;
		}
		else if ( sTmp.indexOf( QRegularExpression( "[0-9][0-9]" ) ) == 0 )
		{
			n = 2;
		}
		else
		{
#ifdef _DEBUG
			Q_ASSERT( sTmp.indexOf( QRegularExpression( "[0-9]" ) ) == 0 );
#endif // _DEBUG
			n = 1;
		}

		bytes[2] = sTmp.left( n ).toUInt();
		nVersionLength = sVersion.size() - sTmp.size() + n;

		if ( eStyle == Style::eMule )
		{
			Q_ASSERT( n == 2 );
			QChar cVersion = sTmp[2];
			Q_ASSERT( cVersion.isLower() );
			ushort nVal = cVersion.unicode() - QChar( 'a' ).unicode();
			Q_ASSERT( nVal >= 0 && nVal <= 26 );
			bytes[1] = ( quint8 )nVal;

			++nVersionLength;
		}

		break;
	}
	default:
		// do nothing
		break;
	}

	m_nVersion = *( quint32* )( &bytes );
	m_sVersion = sVersion.left( nVersionLength );

	qDebug() << "Extracted version number: " << m_nVersion;
}

ClientVersion& ClientVersion::operator=( const ClientVersion& other )
{
	m_eStyle   = other.m_eStyle;
	m_nVersion = other.m_nVersion;
	m_sVersion = other.m_sVersion;

	return *this;
}

bool ClientVersion::operator<( const ClientVersion& other )
{
	return m_nVersion < other.m_nVersion;
}

bool ClientVersion::operator>( const ClientVersion& other )
{
	return m_nVersion > other.m_nVersion;
}

bool ClientVersion::operator<=( const ClientVersion& other )
{
	return m_nVersion <= other.m_nVersion;
}

bool ClientVersion::operator>=( const ClientVersion& other )
{
	return m_nVersion >= other.m_nVersion;
}

ClientVersion::Style ClientVersion::style() const
{
	return m_eStyle;
}

quint32 ClientVersion::version() const
{
	return m_nVersion;
}

QString ClientVersion::versionString() const
{
	return m_sVersion;
}
