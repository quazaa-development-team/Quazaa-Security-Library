/*
** countryrule.h
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

#ifndef COUNTRYRULE_H
#define COUNTRYRULE_H

#include "securerule.h"

#if SECURITY_ENABLE_GEOIP
namespace Security
{

/**
 * @brief The CountryRule class is responsible for the country IP maching.
 */
class CountryRule : public Rule
{
public:
	CountryRule();
	Rule*   getCopy() const;

	bool    parseContent( const QString& sContent );

	bool    match( const EndPoint& oAddress ) const;
	void    toXML( QXmlStreamWriter& oXMLdocument ) const;
};

}
#endif // SECURITY_ENABLE_GEOIP
#endif // COUNTRYRULE_H
