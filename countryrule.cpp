/*
** countryrule.cpp
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

#include "countryrule.h"

#include "debug_new.h"

using namespace Security;

#if SECURITY_ENABLE_GEOIP
CCountryRule::CCountryRule()
{
	m_nType = srContentCountry;
}

bool CCountryRule::parseContent(const QString& sContent)
{
	if ( geoIP.countryNameFromCode( sContent ) != "Unknown" )
	{
		m_sContent = sContent;
		return true;
	}
	return false;
}

bool CCountryRule::match(const CEndPoint& oAddress) const
{
	Q_ASSERT( !oAddress.isNull() && m_nType == srContentCountry );

	if ( m_sContent == oAddress.country() )
		return true;

	return false;
}

void CCountryRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == srContentCountry );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "country" );
	oXMLdocument.writeAttribute( "content", getContentString() );

	CSecureRule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}

CSecureRule* CCountryRule::getCopy() const
{
	return new CCountryRule( *this );
}

#endif // SECURITY_ENABLE_GEOIP
