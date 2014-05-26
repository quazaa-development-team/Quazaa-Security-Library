/*
** clientversion.h
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

#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

//#include <QtGlobal>
#include <QString>

class ClientVersion
{
public:
	enum class Style : quint8 { Unknown = 0, QuazaaDefault = 1, eMule = 2 };

private:
	const Style   m_eStyle;
	quint32       m_nVersion;
	const QString m_sVersion;

public:
	ClientVersion( const QString& sVersion, Style eStyle );

	Style   style() const;
	quint32 version() const;
	QString versionString() const;
};

#endif // CLIENTVERSION_H
