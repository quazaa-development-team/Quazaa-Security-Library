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

HashRule::HashRule()
{
	m_nType = RuleType::Hash;
}

HashVector HashRule::getHashes() const
{
	HashVector result;
	result.reserve( m_lmHashes.size() );

	std::map< CHash::Algorithm, CHash >::const_iterator it = m_lmHashes.begin();
	while ( it != m_lmHashes.end() )
	{
		result.push_back( (*it).second );
		++it;
	}

	return result;
}

void HashRule::setHashes(const HashVector& hashes)
{
	Q_ASSERT( m_nType == RuleType::Hash );

	m_sContent = "";
	m_lmHashes.clear();

	for ( uint n = 0; n < hashes.size(); ++n )
	{
		m_lmHashes.insert( std::pair< CHash::Algorithm, CHash >( hashes[n].getAlgorithm(),
																 hashes[n] ) );

		m_sContent += hashes[n].toURN() + " ";
	}

	m_sContent = m_sContent.trimmed();
}

Rule* HashRule::getCopy() const
{
	return new HashRule( *this );
}

bool HashRule::parseContent(const QString& sContent)
{
	QStringList prefixes;
	prefixes << "urn:sha1:"
			 << "urn:ed2k:"
			 << "urn:ed2khash:"
			 << "urn:tree:tiger:"
			 << "urn:btih:"
			 << "urn:bitprint:"
			 << "urn:md5:";

	HashVector hashes;
	hashes.reserve( prefixes.size() );

	for ( int i = 0; i < prefixes.size(); ++i )
	{
		QString tmp, sHash;
		int pos1, pos2;

		pos1 = sContent.indexOf( prefixes.at(i) );
		if ( pos1 != -1 )
		{
			tmp  = sContent.mid( pos1 );
			int length = CHash::lengthForUrn( prefixes.at(i) ) + prefixes.at(i).length();
			pos2 = tmp.indexOf( "&" );

			qDebug() << "Expected hash length:" << length;
			qDebug() << "Actual hash length:" << pos2;
			qDebug() << "Tmp string length:" << tmp.length();

			if ( pos2 == length )
			{
				qDebug() << "Hash:" << tmp.left( pos2 );
				postLogMessage( LogSeverity::Information,
								QObject::tr( "Hash found for hash rule: %1"
											 ).arg( tmp.left( pos2 ) ) );
				sHash = tmp.left( pos2 );
			}
			else if ( pos2 == -1 && tmp.length() == length )
			{
				postLogMessage( LogSeverity::Information,
								QObject::tr( "Hash found for hash rule at end of string: %1"
											 ).arg( tmp ) );
				sHash = tmp;
			}
			else
			{
				postLogMessage( LogSeverity::Information,
								QObject::tr( "Error extracting hash: %1"
											 ).arg( tmp.left( pos2 ) ) );
				continue;
			}

			CHash* pHash = CHash::fromURN( sHash );
			if ( pHash )
			{
				hashes.push_back( *pHash );
				delete pHash;
			}
			else
				qDebug() << "HashRule: Hash type not recognised.";
		}
	}

	if ( !hashes.empty() )
	{
		setHashes( hashes );
		return true;
	}
	else
	{
		postLogMessage( LogSeverity::Error,
						QObject::tr( "Error: Failed to parse content for hash rule: %1"
									 ).arg( sContent ) );
		return false;
	}
}

void HashRule::reduceByHashPriority(uint nNumberOfHashes)
{
#ifdef _DEBUG
	int n = -1;
#endif

	std::map< CHash::Algorithm, CHash >::iterator it = m_lmHashes.begin();

	while ( it != m_lmHashes.end() && m_lmHashes.size() > nNumberOfHashes )
	{
#ifdef _DEBUG
		Q_ASSERT( n < (*it).second.getAlgorithm() );
		n = (*it).second.getAlgorithm();
#endif

		m_lmHashes.erase( it );
		it = m_lmHashes.begin();
	}
}

bool HashRule::hashEquals(const HashRule& oRule) const
{
	if ( oRule.m_lmHashes.size() != m_lmHashes.size() )
		return false;

	std::map< CHash::Algorithm, CHash >::const_iterator it, itOther;

	it  = m_lmHashes.begin();
	itOther = oRule.m_lmHashes.begin();

	while ( it != m_lmHashes.end() )
	{
		itOther = oRule.m_lmHashes.find( (*it).second.getAlgorithm() );
		if ( (*it).second != (*itOther).second )
			return false;

		++it;
	}

	return true;
}

bool HashRule::match(const CQueryHit* const pHit) const
{
	return match( pHit->m_lHashes );
}
bool HashRule::match(const HashVector& lHashes) const
{
	std::map< CHash::Algorithm, CHash >::const_iterator it;
	quint8 nCount = 0;

	foreach ( CHash oHash, lHashes )
	{
		it = m_lmHashes.find( oHash.getAlgorithm() );

		if ( it != m_lmHashes.end() )
		{
			++nCount;

			if ( oHash != (*it).second )
				return false;
		}
	}

	return nCount;
}

void HashRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == RuleType::Hash );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "hash" );
	oXMLdocument.writeAttribute( "content", getContentString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
