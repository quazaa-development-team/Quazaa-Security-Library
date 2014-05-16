/*
** securerule.cpp
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

#include "securerule.h"

#include "contentrule.h"
#include "countryrule.h"
#include "hashrule.h"
#include "iprangerule.h"
#include "iprule.h"
#include "regexprule.h"
#include "useragentrule.h"

#include "securitymanager.h"

#if QT_VERSION >= 0x050000
#  include <QRegularExpression>
#else
#  include <QRegExp>
#endif

#include "debug_new.h"

using namespace Security;

IDProvider<ID> Rule::m_oIDProvider;

Rule::Rule() :
	m_nToday( 0 ),
	m_nTotal( 0 ),
	m_tExpire( RuleTime::Forever )
{
	// This invalidates the rule as long as it does not contain any useful content.
	m_nType   = RuleType::Undefined;

	m_nAction = RuleAction::Deny;
	m_idUUID  = QUuid::createUuid();

	m_nGUIID  = m_oIDProvider.aquire();
}

Rule::Rule( const Rule& pRule )
{
	// The usage of a custom copy constructor makes sure each rule gets a distinct GUI ID.
	m_nType      = pRule.m_nType;
	m_sContent   = pRule.m_sContent;
	m_nToday     = pRule.m_nToday;
	m_nTotal     = pRule.m_nTotal;
	m_nAction    = pRule.m_nAction;
	m_idUUID     = pRule.m_idUUID;
	m_tExpire    = pRule.m_tExpire;
	m_sComment   = pRule.m_sComment;
	m_bAutomatic = pRule.m_bAutomatic;

	m_nGUIID     = m_oIDProvider.aquire();
}

Rule::~Rule()
{
	m_oIDProvider.release( m_nGUIID );
}

Rule* Rule::getCopy() const
{
	// This method should never be called.
	Q_ASSERT( false );

	return new Rule( *this );
}

bool Rule::operator==( const Rule& pRule ) const
{
	// we don't compare GUI IDs or hit counters
	return m_nType      == pRule.m_nType      &&
		   m_nAction    == pRule.m_nAction    &&
		   m_tExpire    == pRule.m_tExpire    &&
		   m_bAutomatic == pRule.m_bAutomatic &&
		   m_idUUID     == pRule.m_idUUID     &&
		   m_sContent   == pRule.m_sContent   &&
		   m_sComment   == pRule.m_sComment;
}

bool Rule::operator!=( const Rule& pRule ) const
{
	return !( *this == pRule );
}

bool Rule::parseContent( const QString& )
{
	Q_ASSERT( false );
	return false;
}

QString Rule::getContentString() const
{
	Q_ASSERT( m_nType != RuleType::Undefined );

	return m_sContent;
}

bool Rule::match( const EndPoint& ) const
{
	return false;
}
/*bool Rule::match(const QString&) const
{
	return false;
}*/
bool Rule::match( const QueryHit* const ) const
{
	return false;
}
bool Rule::match( const QList<QString>&, const QString& ) const
{
	return false;
}

void Rule::save( const Rule* const pRule, QDataStream& oStream )
{
	// we don't store GUI IDs and session hit counter
	oStream << ( quint8 )( pRule->m_nType );
	oStream << ( quint8 )( pRule->m_nAction );
	oStream << pRule->m_sComment;
	oStream << pRule->m_idUUID.toString();
	oStream << pRule->m_tExpire;
	oStream << pRule->m_nTotal.loadAcquire();
	oStream << pRule->m_bAutomatic;
	oStream << pRule->getContentString();

	if ( pRule->m_nType == RuleType::UserAgent )
	{
		oStream << ( ( UserAgentRule* )pRule )->getRegExp();
	}
	else if ( pRule->m_nType == RuleType::Content )
	{
		oStream << ( ( ContentRule* )pRule )->getAll();
	}
}

void Rule::load( Rule*& pRule, QDataStream& fsFile, int )
{
	if ( pRule )
	{
		delete pRule;
		pRule = NULL;
	}

	quint8      nType;
	quint8      nAction;
	QString     sComment;
	QString     sUUID;
	quint32     tExpire;
	quint32     nTotal;
	bool        bAutomatic;
	QString     sContent;

	fsFile >> nType;
	fsFile >> nAction;
	fsFile >> sComment;
	fsFile >> sUUID;
	fsFile >> tExpire;
	fsFile >> nTotal;
	fsFile >> bAutomatic;
	fsFile >> sContent;

	bool	bTmp = true;

	switch ( nType )
	{
	case RuleType::Undefined:
		// contentless rule
		pRule = new Rule();
		Q_ASSERT( false );
		break;

	case RuleType::IPAddress:
		pRule = new IPRule();
		break;

	case RuleType::IPAddressRange:
		pRule = new IPRangeRule();
		break;

#if SECURITY_ENABLE_GEOIP
	case RuleType::Country:
		pRule = new CountryRule();
		break;
#endif

	case RuleType::Hash:
		pRule = new HashRule();
		break;

	case RuleType::RegularExpression:
		pRule = new RegularExpressionRule();
		break;

	case RuleType::UserAgent:
		pRule = new UserAgentRule();
		fsFile >> bTmp;
		( ( UserAgentRule* )pRule )->setRegExp( bTmp );
		break;

	case RuleType::Content:
		pRule = new ContentRule();
		fsFile >> bTmp;
		( ( ContentRule* )pRule )->setAll( bTmp );
		break;

	default:
		pRule = new Rule();
#if SECURITY_ENABLE_GEOIP
		Q_ASSERT( false );
#else
		Q_ASSERT( nType == RuleType::Country )
#endif
		break;
	}

	pRule->m_nAction    = ( RuleAction::Action )nAction;
	pRule->m_sComment   = sComment;
	pRule->m_idUUID     = QUuid( sUUID );
	pRule->m_tExpire    = tExpire;
	pRule->m_nTotal.storeRelease( nTotal );
	pRule->m_bAutomatic = bAutomatic;
	pRule->parseContent( sContent );
}

/**
 * @brief CSecureRule::isExpired allows to check whether a rule has expired.
 * @param tNow indicates the current time in seconds since 1.1.1970UTC
 * @param bSession indicates whether this is the end of the session/start of a new session. In both
 * cases, set this to true and the return value for session ban rules will be true.
 * @return true if the rule has expired, false otherwise
 */
bool Rule::isExpired( quint32 tNow, bool bSession ) const
{
	switch ( m_tExpire )
	{
	case RuleTime::Forever:
		return false;

	case RuleTime::Session:
		return bSession;

	default:
		return m_tExpire < tNow;
	}
}

/**
 * @brief Rule::setExpiryTime
 * @param tExpire
 */
void Rule::setExpiryTime( const quint32 tExpire )
{
	m_tExpire = tExpire;
}

/**
 * @brief Rule::addExpiryTime
 * @param tAdd
 */
void Rule::addExpiryTime( const quint32 tAdd )
{
	if ( m_tExpire != RuleTime::Session && m_tExpire != RuleTime::Forever )
	{
		m_tExpire += tAdd;
	}
}

/**
 * @brief CSecureRule::getExpiryTime allows to access the expiry time of a rule.
 * @return srIndefinite = 0, srSession = 1 or the time in seconds since 1.1.1970UTC when the rule
 * will/has expire(d)
 */
quint32 Rule::getExpiryTime() const
{
	return m_tExpire;
}

/**
 * @brief mergeInto merges this Rule into pDestination.
 * Takes the higher expiration time, m_bAutomatic if it is false, adds the today and total
 * counters and modifies the comment string to indicate the merge. Overwrites the RuleAction of
 * pDestination.
 * Requires Locking: RW
 */
void Rule::mergeInto( Rule* pDestination )
{
	if ( m_sContent != pDestination->m_sContent || m_nType != pDestination->m_nType )
	{
		Q_ASSERT( m_nType    == pDestination->m_nType    );
	}

	if ( !m_bAutomatic )
	{
		pDestination->m_bAutomatic = false;    // don't overwrite manual with automatic rules
	}

	if ( m_tExpire == RuleTime::Forever )
	{
		pDestination->m_tExpire = RuleTime::Forever; // don't overwrite indefinite expiry time
	}
	else if ( m_tExpire > pDestination->m_tExpire )
	{
		pDestination->m_tExpire = m_tExpire;
	}

	pDestination->m_nAction = m_nAction;


#ifdef _DEBUG // allows to easily spot multiply merged rules in debug builds
	if ( !pDestination->m_sComment.contains( " (AutoMerged Rule)" ) )
	{
		pDestination->m_sComment += " (AutoMerged Rule)";
	}
	else
	{
		pDestination->m_sComment += "+";
	}
#else
	if ( !pDestination->m_sComment.endsWith( " (AutoMerged Rule)" ) )
	{
		pDestination->m_sComment += " (AutoMerged Rule)";
	}
#endif

	pDestination->m_nToday.fetchAndAddRelaxed( m_nToday.load() );
	pDestination->m_nTotal.fetchAndAddRelaxed( m_nTotal.load() );

	securityManager.emitUpdate( pDestination->m_nGUIID );
}

/**
 * @brief CSecureRule::count increases the total and today hit counters by one each.
 * Requires Locking: /
 */
void Rule::count( uint nCount )
{
	m_nToday.fetchAndAddOrdered( nCount );
	m_nTotal.fetchAndAddOrdered( nCount );
}

/**
 * @brief CSecureRule::resetCount resets total and today hit counters to 0.
 * Requires Locking: /
 */
void Rule::resetCount()
{
	m_nToday.fetchAndStoreOrdered( 0 );
	m_nTotal.fetchAndAddOrdered( 0 );
}

/**
 * @brief CSecureRule::getTodayCount allows to access the today hit counter.
 * @return the value of the today hit counter.
 * Requires Locking: /
 */
quint32 Rule::getTodayCount() const
{
	return m_nToday.loadAcquire();
}

/**
 * @brief CSecureRule::getTotalCount allows to access the total hit counter.
 * @return the value of the total hit counter.
 * Requires Locking: /
 */
quint32 Rule::getTotalCount() const
{
	return m_nTotal.loadAcquire();
}

/**
 * @brief CSecureRule::loadTotalCount allows to access the total hit counter.
 * @param nTotal the new value of the total hit counter.
 * Requires Locking: /
 */
void Rule::loadTotalCount( quint32 nTotal )
{
	m_nTotal.storeRelease( nTotal );
}

/**
 * @brief CSecureRule::type allows to access the type of this rule.
 * @return the rule type.
 * Requires Locking: R
 */
RuleType::Type Rule::type() const
{
	return m_nType;
}

Rule* Rule::fromXML( QXmlStreamReader& oXMLdocument, float nVersion )
{
	QXmlStreamAttributes attributes = oXMLdocument.attributes();

	const QString sType = attributes.value( "type" ).toString();

	if ( sType.isEmpty() )
	{
		return NULL;
	}

	Rule* pRule = NULL;

	if ( sType.compare( "address", Qt::CaseInsensitive ) == 0 )
	{
		QString sAddress = attributes.value( "address" ).toString();

		if ( nVersion < 2.0 )
		{
			const QString sMask = attributes.value( "mask" ).toString().trimmed();

			if ( sMask.isEmpty() || sMask == "255.255.255.255" ) // old style IPv4 rule
			{
				pRule = new IPRule();
				if ( !pRule->parseContent( sAddress ) )
				{
					delete pRule;
					pRule = NULL;
				}
			}
			else // old style range rule
			{
				QHostAddress oIP( sAddress );
				QHostAddress oMask( sMask );

				if ( oIP.protocol()   == QAbstractSocket::IPv4Protocol ||
					 oMask.protocol() == QAbstractSocket::IPv4Protocol )
				{
					// Reference matching code (Shareaza)
					// pTest is the IP to test, pMask the netmask and pBase the range rule base IP
					// if ( ( ( *pTest ) & ( *pMask ) ) == ( *pBase ) )
					// {
					//     return TRUE;
					// }

					quint32 nMask = oMask.toIPv4Address();
					quint32 nIP   = oIP.toIPv4Address() & nMask; // this clears the lower bits

					quint32 nStartIP = nIP;
					quint32 nEndIP   = nIP | ~nMask; // this sets all the lower bits to 1

					QString sStartIP = QHostAddress( nStartIP ).toString();
					QString sEndIP   = QHostAddress( nEndIP ).toString();

					pRule = new IPRangeRule();
					if ( !pRule->parseContent( QString( "%1-%2" ).arg( sStartIP, sEndIP ) ) )
					{
						delete pRule;
						pRule = NULL;
					}
				}
			}
		}
		else
		{
			pRule = new IPRule();

			if ( !pRule->parseContent( sAddress ) )
			{
				delete pRule;
				pRule = NULL;
			}
		}
	}
	else if ( sType.compare( "addressrange", Qt::CaseInsensitive ) == 0 )
	{
		QString sStartAddress = attributes.value( "startaddress" ).toString();
		QString sEndAddress = attributes.value( "endaddress" ).toString();

		pRule = new IPRangeRule();
		if ( !pRule->parseContent( QString( "%1-%2" ).arg( sStartAddress, sEndAddress ) ) )
		{
			delete pRule;
			pRule = NULL;
		}
	}
	else if ( sType.compare( "hash", Qt::CaseInsensitive ) == 0 )
	{
		pRule = new HashRule();
		if ( !pRule->parseContent( attributes.value( "content" ).toString() ) )
		{
			delete pRule;
			pRule = NULL;
		}
	}
	else if ( sType.compare( "regexp", Qt::CaseInsensitive ) == 0 )
	{
		pRule = new RegularExpressionRule();
		if ( !pRule->parseContent( attributes.value( "content" ).toString() ) )
		{
			delete pRule;
			pRule = NULL;
		}
	}
	else if ( sType.compare( "content", Qt::CaseInsensitive ) == 0 )
	{
		const QString sMatch = attributes.value( "match" ).toString();
		const QString sContent = attributes.value( "content" ).toString();

		const QString sUrn = sContent.left( 4 );

		if ( nVersion < 2.0 )
		{
			// This handles old v1.0 style Shareaza RegExp rules.
			if ( !sMatch.compare( "regexp", Qt::CaseInsensitive ) )
			{
				pRule = new RegularExpressionRule();
				if ( !pRule->parseContent( sContent ) )
				{
					delete pRule;
					pRule = NULL;
				}
			}
			// This handles "old style" Shareaza hash rules.
			else if ( !sUrn.compare( "urn:", Qt::CaseInsensitive ) )
			{
				pRule = new HashRule();
				if ( !pRule->parseContent( sContent ) )
				{
					delete pRule;
					pRule = NULL;
				}
			}
		}

		if ( !pRule )
		{
			bool all = ( !sMatch.compare( "all", Qt::CaseInsensitive ) );

			if ( all || !sMatch.compare( "any", Qt::CaseInsensitive ) )
			{
				pRule = new ContentRule();
				if ( !pRule->parseContent( sContent ) )
				{
					delete pRule;
					pRule = NULL;
				}
				else
				{
					( ( ContentRule* )pRule )->setAll( all );
				}
			}
		}
	}
#if SECURITY_ENABLE_GEOIP
	else if ( !sType.compare( "country", Qt::CaseInsensitive ) )
	{
		pRule = new CountryRule();
		if ( !pRule->parseContent( attributes.value( "content" ).toString() ) )
		{
			delete pRule;
			pRule = NULL;
		}
	}
#endif // SECURITY_ENABLE_GEOIP

	if ( !pRule )
	{
		return NULL;
	}

	const QString sAction = attributes.value( "action" ).toString();

	if ( sAction.compare( "deny", Qt::CaseInsensitive ) == 0 || sAction.isEmpty() )
	{
		pRule->m_nAction = RuleAction::Deny;
	}
	else if ( sAction.compare( "accept", Qt::CaseInsensitive ) == 0 )
	{
		pRule->m_nAction = RuleAction::Accept;
	}
	else if ( sAction.compare( "null", Qt::CaseInsensitive ) == 0 )
	{
		pRule->m_nAction = RuleAction::None;
	}
	else
	{
		delete pRule;
		return NULL;
	}

	const QString sAutomatic = attributes.value( "automatic" ).toString();
	if ( sAutomatic == "true" )
	{
		pRule->m_bAutomatic = true;
	}
	else
	{
		pRule->m_bAutomatic = false;
	}

	pRule->m_sComment = attributes.value( "comment" ).toString().trimmed();

	QString sExpire = attributes.value( "expire" ).toString();
	if ( !sExpire.compare( "indefinite", Qt::CaseInsensitive ) )
	{
		pRule->m_tExpire = RuleTime::Forever;
	}
	else if ( !sExpire.compare( "session", Qt::CaseInsensitive ) )
	{
		pRule->m_tExpire = RuleTime::Session;
	}
	else
	{
		pRule->m_tExpire = sExpire.toUInt();
	}

	QString sUUID = attributes.value( "uuid" ).toString();
	if ( sUUID.isEmpty() )
	{
		sUUID = attributes.value( "guid" ).toString();
	}

	if ( sUUID.isEmpty() )
	{
		pRule->m_idUUID = QUuid::createUuid();
	}
	else
	{
		pRule->m_idUUID = QUuid( sUUID );
	}

	return pRule;
}

// Contains default code for XML generation.
void Rule::toXML( const Rule& oRule, QXmlStreamWriter& oXMLdocument )
{
	QString sValue;

	// Write rule action to XML file.
	switch ( oRule.m_nAction )
	{
	case RuleAction::None:
		sValue = "null";
		break;
	case RuleAction::Accept:
		sValue = "accept";
		break;
	case RuleAction::Deny:
		sValue = "deny";
		break;
	default:
		Q_ASSERT( false );
	}
	oXMLdocument.writeAttribute( "action", sValue );

	if ( oRule.m_bAutomatic )
	{
		oXMLdocument.writeAttribute( "automatic", "true" );
	}

	// Write expiry date.
	if ( oRule.m_tExpire == RuleTime::Forever )
	{
		sValue = "indefinite";
	}
	else if ( oRule.m_tExpire == RuleTime::Session )
	{
		sValue = "session";
	}
	else
	{
		sValue = "%1";
		sValue.arg( oRule.m_tExpire );
	}
	oXMLdocument.writeAttribute( "expire", sValue );

	// Write rule UUID.
	sValue = oRule.m_idUUID.toString();
	oXMLdocument.writeAttribute( "uuid", sValue );

	// Write user comment.
	if ( !( oRule.m_sComment.isEmpty() ) )
	{
		oXMLdocument.writeAttribute( "comment", oRule.m_sComment );
	}
}

void Rule::toXML( QXmlStreamWriter& ) const
{
	Q_ASSERT( false );
}
