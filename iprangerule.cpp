/*
** iprangerule.cpp
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

#include "iprangerule.h"

#include "debug_new.h"

using namespace Security;

CIPRangeRule::CIPRangeRule()
{
	m_nType = srContentAddressRange;
}

CSecureRule* CIPRangeRule::getCopy() const
{
	return new CIPRangeRule( *this );
}

bool CIPRangeRule::parseContent(const QString& sContent)
{
	QPair<QHostAddress, int> oPair = QHostAddress::parseSubnet( sContent );

	if ( oPair != qMakePair( QHostAddress(), -1 ) )
	{
		m_oSubNet = oPair;
		m_sContent = m_oSubNet.first.toString() + "/" + QString::number( m_oSubNet.second );
		return true;
	}
	return false;
}

QHostAddress CIPRangeRule::IP() const
{
	return m_oSubNet.first;
}

int CIPRangeRule::mask() const
{
	return m_oSubNet.second;
}

bool CIPRangeRule::match(const CEndPoint& oAddress) const
{
#ifdef _DEBUG
	Q_ASSERT( m_nType == srContentAddressRange );
#endif //_DEBUG

	return oAddress.isInSubnet( m_oSubNet );
}

void CIPRangeRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == srContentAddressRange );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "address" );
	oXMLdocument.writeAttribute( "address", m_oSubNet.first.toString() );
	oXMLdocument.writeAttribute( "mask", QString( m_oSubNet.second ) );

	CSecureRule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}