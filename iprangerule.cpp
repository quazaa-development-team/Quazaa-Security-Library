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

#include "securitymanager.h"

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
	QStringList lAddresses = sContent.split("-");

	CEndPoint oStartAddress, oEndAddress;
	if ( lAddresses.size() == 2 &&
		 oStartAddress.setAddress( lAddresses.at( 0 ) ) &&
		 oEndAddress.setAddress( lAddresses.at( 1 ) ) )
	{
		m_oStartIP = oStartAddress;
		m_oEndIP   = oEndAddress;
		m_sContent = sContent;
		return true;
	}

	qDebug() << "[Security Error] Could not parse the following as IP range rule: "
			 << sContent;
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

/**
 * @brief merge merges pOther into this rule.
 * Note that this changes only the ranges of this rule.
 * Note also that it is required for something of this rule to remain after merging.
 * In case this rule is split into two, the second half is returned as a new rule.
 * @param pOther : the rule to merge into this one; Set to NULL if superfluous after merging.
 * @return NULL except if pOther is contained within this rule in which case a Rule is returned
 * which represents the part of this rules range after the range of pOther.
 */
IPRangeRule* IPRangeRule::merge(IPRangeRule*& pOther)
{
	Q_ASSERT( pOther->m_oEndIP >= pOther->m_oStartIP );
	Q_ASSERT(         m_oEndIP >=         m_oStartIP );

	// TODO: All other asserts in this method shall be removed for Quazaa 1.0.0.0

	bool bThisContainsOtherStartIP = contains( pOther->startIP() );
	bool bThisContainsOtherEndIP   = contains( pOther->endIP() );

	IPRangeRule* pReturn = NULL;

	if ( bThisContainsOtherStartIP && bThisContainsOtherEndIP )
	{
		if ( m_nAction != pOther->m_nAction )
		{
			if ( pOther->m_nAction == RuleAction::None )
			{
				// if the other rule has no defined action, the action of the existing rule prevails
				delete pOther;
				pOther = NULL;
			}
			else
			{
				// Split this rule into two parts: this before pOther, pNewRule after pOther
				IPRangeRule* pNewRule = (IPRangeRule*)getCopy();
				pNewRule->m_oStartIP = pOther->m_oEndIP;
				++pNewRule->m_oStartIP;

				// adjust our own end IP
				m_oEndIP = pOther->m_oStartIP;
				--m_oEndIP;

				Q_ASSERT( pNewRule->m_oEndIP >= pNewRule->m_oStartIP );
				Q_ASSERT(           m_oEndIP >=           m_oStartIP );

				// Update GUI relevant info
				pNewRule->m_sComment += QObject::tr( " (Split by range merging)" );
				pNewRule->m_sContent = pNewRule->m_oStartIP.toString() + "-" +
									   pNewRule->m_oEndIP.toString();

				// return remaining second part of this rule
				pReturn = pNewRule;
			}
		}
		else
		{
			pOther->mergeInto( this );

			delete pOther;
			pOther = NULL;
		}
	}
	else if ( bThisContainsOtherStartIP )
	{
		m_oEndIP = pOther->m_oStartIP;
		--m_oEndIP;

		Q_ASSERT( m_oEndIP >= m_oStartIP );
	}
	else if ( bThisContainsOtherEndIP )
	{
		m_oStartIP = pOther->m_oEndIP;
		++m_oStartIP;

		Q_ASSERT( m_oEndIP >= m_oStartIP );
	}

	// make sure to update GUI relevant info
	if ( pOther )
	{
		pOther->m_sContent = pOther->m_oStartIP.toString() + "-" +
							 pOther->m_oEndIP.toString();
	}

	m_sContent = m_oStartIP.toString() + "-" + m_oEndIP.toString();
	securityManager.emitUpdate( m_nGUIID );

	return pReturn;
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
