/*
** hashrule.cpp
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

#include "hashrule.h"

#include "debug_new.h"

using namespace Security;

CHashRule::CHashRule()
{
	m_nType = srContentHash;
}

CSecureRule* CHashRule::getCopy() const
{
	return new CHashRule( *this );
}

bool CHashRule::parseContent(const QString& sContent)
{
	QString tmp, sHash;
	int pos1, pos2;
	QList< CHash > lHashes;

	QString prefixes[5] = { "urn:sha1:", "urn:ed2k:", "urn:tree:tiger:", "urn:btih:", "urn:md5:" };
	quint8 lengths[5] = { 32 + 9, 32 + 9, 39 + 15, 32 + 9, 32 + 8 };

	for ( quint8 i = 0; i < 5; ++i )
	{
		sHash = "";

		pos1 = sContent.indexOf( prefixes[i] );
		if ( pos1 != -1 )
		{
			tmp  = sContent.mid( pos1 );
			pos2 = tmp.indexOf( ' ' );

			if ( pos2 == lengths[i] )
			{
				sHash = tmp.left( pos2 );
			}
			else if ( pos2 == -1 && tmp.length() == lengths[i] )
			{
				sHash = tmp;
			}
			else
			{
//				theApp.Message( MSG_ERROR, IDS_SECURITY_XML_HASH_RULE_IMPORT_ERROR );
				continue;
			}

			lHashes.append( *CHash::FromURN( sHash ) );
		}
	}

	if ( !lHashes.isEmpty() )
	{
		setHashes( lHashes );
		return true;
	}
	else
	{
//		theApp.Message( MSG_ERROR, IDS_SECURITY_XML_HASH_RULE_IMPORT_FAIL );
		return false;
	}
}

QList< CHash > CHashRule::getHashes() const
{
	QList< CHash > result;
	foreach ( CHash oHash, m_Hashes )
	{
		result.append( oHash );
	}

	return result;
}

void CHashRule::setHashes(const QList< CHash >& hashes)
{
	Q_ASSERT( m_nType == srContentHash );

	m_sContent = "";

	foreach ( CHash oHash, hashes )
	{
		m_Hashes.insert( oHash.getAlgorithm(), oHash );
		m_sContent += oHash.ToURN();
		m_sContent += " ";
	}

	m_sContent = m_sContent.trimmed();
}

bool CHashRule::hashEquals(CHashRule& oRule) const
{
	if ( oRule.m_Hashes.size() != m_Hashes.size() )
		return false;

	QMap< CHash::Algorithm, CHash >::const_iterator i, j;

	i = m_Hashes.begin();
	j = oRule.m_Hashes.begin();

	while ( i != m_Hashes.end() )
	{
		j = oRule.m_Hashes.find( (*i).getAlgorithm() );
		if ( *i != *j )
			return false;

		++i;
	}

	return true;
}

bool CHashRule::match(const CQueryHit* const pHit) const
{
	return match( pHit->m_lHashes );
}
bool CHashRule::match(const QList<CHash>& lHashes) const
{
	QMap< CHash::Algorithm, CHash >::const_iterator i;
	quint8 nCount = 0;

	foreach ( CHash oHash, lHashes )
	{
		i = m_Hashes.find( oHash.getAlgorithm() );

		if ( i != m_Hashes.end() )
		{
			++nCount;

			if ( oHash != *i )
				return false;
		}
	}

	return nCount;
}

void CHashRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == srContentHash );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "hash" );
	oXMLdocument.writeAttribute( "content", getContentString() );

	CSecureRule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
