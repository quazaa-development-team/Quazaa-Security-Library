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

IPRangeRule::IPRangeRule()
{
	m_nType = RuleType::IPAddressRange;
}

Rule* IPRangeRule::getCopy() const
{
	return new IPRangeRule( *this );
}

bool IPRangeRule::parseContent(const QString& sContent)
{
	QStringList addresses = sContent.split("-");

	CEndPoint oStartAddress;
	CEndPoint oEndAddress;
	if ( oStartAddress.setAddress( addresses.at(0) ) && oEndAddress.setAddress( addresses.at(1) ) )
	{
		m_oStartIP = oStartAddress;
		m_oEndIP = oEndAddress;
		m_sContent = sContent;
		return true;
	}
	return false;
}

CEndPoint IPRangeRule::startIP() const
{
	return m_oStartIP;
}

CEndPoint IPRangeRule::endIP() const
{
	return m_oEndIP;
}

IPRangeRule* IPRangeRule::merge(IPRangeRule*& pOther)
{
	Q_ASSERT( pOther->m_oEndIP >= pOther->m_oStartIP );
	Q_ASSERT(         m_oEndIP >=         m_oStartIP );

	bool bContainsOtherStartIP = contains( pOther->startIP() );
	bool bContainsOtherEndIP   = contains( pOther->endIP() );

	if ( bContainsOtherStartIP && bContainsOtherEndIP )
	{
		if ( m_nAction != pOther->m_nAction )
		{
			if ( pOther->m_nAction == RuleAction::None )
			{
				delete pOther;
				pOther = NULL;
			}
			else
			{
				IPRangeRule* pNewRule = (IPRangeRule*)getCopy();
				pNewRule->m_oStartIP = pOther->m_oEndIP;
				++pNewRule->m_oStartIP;

				m_oEndIP = pOther->m_oStartIP;
				--m_oEndIP;

				Q_ASSERT( pNewRule->m_oEndIP >= pNewRule->m_oStartIP );
				Q_ASSERT(           m_oEndIP >=           m_oStartIP );

				return pNewRule;
			}
		}
		else
		{
			pOther->mergeInto( this );

			delete pOther;
			pOther = NULL;
		}
	}
	else if ( bContainsOtherStartIP )
	{
		m_oEndIP = pOther->m_oStartIP;
		--m_oEndIP;

		Q_ASSERT( m_oEndIP >= m_oStartIP );
	}
	else if ( bContainsOtherEndIP )
	{
		m_oStartIP = pOther->m_oEndIP;
		++m_oStartIP;

		Q_ASSERT( m_oEndIP >= m_oStartIP );
	}

	return NULL;
}

bool IPRangeRule::contains(const CEndPoint& oAddress) const
{
#ifdef _DEBUG
	Q_ASSERT( m_nType == RuleType::IPAddressRange );
#endif //_DEBUG

	if ( oAddress > m_oStartIP && oAddress < m_oEndIP)
		return true;

	return false;
}

bool IPRangeRule::match(const CEndPoint& oAddress) const
{
	if ( oAddress >= m_oStartIP && oAddress <= m_oEndIP )
		return true;

	return false;
}

void IPRangeRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == RuleType::IPAddressRange );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "addressrange" );
	oXMLdocument.writeAttribute( "startaddress", m_oStartIP.toString() );
	oXMLdocument.writeAttribute( "endaddress", m_oEndIP.toString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
