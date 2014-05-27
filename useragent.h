/*
** useragent.h
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

#ifndef USERAGENT_H
#define USERAGENT_H

#include "clientversion.h"

class UserAgent
{
public:
	enum class Style : quint8 { Unknown = 0,        // unable to parse
								QuazaaDefault = 1,  // client name + d.d.d.d, where d is 0-255
								GnucDNA = 2,        // like quazaa default, only 2 times
								eMule = 3,          // client name + d.d[a-z] (+ suffix)
								Simple = 4          // client name + d.d      (+ suffix)
							  };
private:
	const QString m_sUserAgent;
	Style         m_eStyle;

	QString       m_sClientName;
	ClientVersion m_oClientVersion;

	QString       m_sLibraryName;
	ClientVersion m_oLibraryVersion;

public:
	UserAgent( const QString& sUserAgent );

	bool operator<( const UserAgent& other );
	bool operator>( const UserAgent& other );

	bool operator<=( const UserAgent& other );
	bool operator>=( const UserAgent& other );

	/**
	 * @brief operator == compares two UserAgents.
	 * @param other  The other UserAgent.
	 * @return <code>true</code> if completely equal or equal in name only and at least one of the
	 * versions is 0; <br><code>false</code> otherwise
	 */
	bool operator==( const UserAgent& other );
	bool operator!=( const UserAgent& other );

	void parse( const QString& sWhat, const Style eHow,
				QString& sNameDest, ClientVersion& rClientDest );

	QString userAgentString() const;
	QString clientName() const;
	ClientVersion clientVersion() const;
	QString libraryName() const;
	ClientVersion libraryVersion() const;
};

#endif // USERAGENT_H
