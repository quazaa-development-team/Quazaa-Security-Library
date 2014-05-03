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

const HashSet& HashRule::getHashes() const
{
	Q_ASSERT( m_nType == RuleType::Hash );

	return m_vHashes;
}

void HashRule::setHashes( const HashSet& hashes )
{
	Q_ASSERT( m_nType == RuleType::Hash );

	m_sContent = "";
	m_vHashes = HashSet( hashes );

	for ( quint8 i = 0, nSize = hashes.size(); i < nSize; ++i )
	{
		m_sContent += hashes[i]->toURN() + " ";
	}

	m_sContent = m_sContent.trimmed();
}

Rule* HashRule::getCopy() const
{
	return new HashRule( *this );
}

bool HashRule::parseContent( const QString& sContent )
{
	QStringList prefixes;
	prefixes << "urn:sha1:"
			 << "urn:ed2k:"
			 << "urn:ed2khash:"
			 << "urn:tree:tiger:"
			 << "urn:btih:"
			 << "urn:bitprint:"
			 << "urn:md5:";

	HashSet vHashes;

	for ( int i = 0; i < prefixes.size(); ++i )
	{
		QString tmp, sHash;
		int pos1, pos2;

		pos1 = sContent.indexOf( prefixes.at( i ) );
		if ( pos1 != -1 )
		{
			tmp  = sContent.mid( pos1 );
			int length = CHash::lengthForUrn( prefixes.at( i ) ) + prefixes.at( i ).length();
			pos2 = tmp.indexOf( "&" );

			qDebug() << "Expected hash length:" << length;
			qDebug() << "Actual hash length:"   << pos2;
			qDebug() << "Tmp string length:"    << tmp.length();

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
				vHashes.insert( pHash );
			}
			else
			{
				qDebug() << "HashRule: Hash type not recognised.";
			}
		}
	}

	if ( !vHashes.empty() )
	{
		setHashes( vHashes );
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

void HashRule::simplifyByHashPriority( quint8 nNumberOfHashes )
{
	m_vHashes.simplifyByHashPriority( nNumberOfHashes );
}

bool HashRule::hashEquals( const HashRule& oRule ) const
{
	return m_vHashes == oRule.m_vHashes;
}

bool HashRule::match( const QueryHit* const pHit ) const
{
	return match( pHit->m_vHashes );
}
bool HashRule::match( const HashSet& vHashes ) const
{
	return m_vHashes.matches( vHashes );
}

void HashRule::toXML( QXmlStreamWriter& oXMLdocument ) const
{
	Q_ASSERT( m_nType == RuleType::Hash );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "hash" );
	oXMLdocument.writeAttribute( "content", getContentString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
