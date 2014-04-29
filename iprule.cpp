/*
** iprule.cpp
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

#include "iprule.h"

#include "debug_new.h"

using namespace Security;

IPRule::IPRule()
{
	m_nType = RuleType::IPAddress;
}

Rule* IPRule::getCopy() const
{
	return new IPRule( *this );
}

bool IPRule::parseContent(const QString& sContent)
{
	EndPoint oAddress;
	if ( oAddress.setAddress( sContent ) )
	{
		m_oIP = oAddress;
		m_sContent = oAddress.toString();
		return true;
	}
	return false;
}

QHostAddress IPRule::IP() const
{
	return m_oIP;
}

void IPRule::setIP(const QHostAddress& oIP )
{
	m_oIP = oIP;
	m_sContent = oIP.toString();
}

bool IPRule::match(const EndPoint& oAddress) const
{
	Q_ASSERT( !oAddress.isNull() && m_nType == RuleType::IPAddress );

	if ( !oAddress.isNull() && oAddress == m_oIP )
	{
		return true;
	}
	return false;
}

void IPRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == RuleType::IPAddress );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "address" );
	oXMLdocument.writeAttribute( "address", getContentString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
