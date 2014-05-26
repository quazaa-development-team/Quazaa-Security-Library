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

#include "clientversion.h"

ClientVersion::ClientVersion( const QString& sVersion , Style eStyle ) :
	m_eStyle( eStyle ),
	m_sVersion( sVersion )
{
	switch ( eStyle )
	{
	case Style::QuazaaDefault:
	case Style::eMule:
	default:
	}
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
