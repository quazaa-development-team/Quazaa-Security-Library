/*
** securitymanager.cpp
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

#include <QDir>
#include <QDateTime>
#include <QMetaType>

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "securitymanager.h"

#include "debug_new.h"

Security::Manager securityManager;
using namespace Security;

bool IPRangeLessThan(const IPRangeRule *rule1, const IPRangeRule *rule2)
{
	return rule1->startIP() < rule2->startIP();
}

bool IPLessThan(const IPRule *rule1, const IPRule *rule2)
{
	return rule1->IP() < rule2->IP();
}

/**
 * @brief Manager::ruleInfoSignal
 */
//const char* Manager::ruleInfoSignal = SIGNAL( ruleInfo( Rule* ) );

// QApplication hasn't been started when the global definition creates this object, so
// no qt specific calls (for example connect() or emit signal) may be used over here.
// See initialize() for that kind of initializations.
Manager::Manager() :
	m_bEnableCountries( false ),
	m_bLogIPCheckHits( false ),
	m_tRuleExpiryInterval( 600 * 1000 ),
	m_bUnsaved( false ),
	m_bExpiryRequested( false ),
	m_bIgnorePrivateIPs( false ),
	m_bIsLoading( false ),
	m_bNewRulesLoaded( false ),
	m_nPendingOperations( 0 ),
	m_bDenyPolicy( false )
{
}

Manager::~Manager()
{
}

/**
 * @brief Manager::getCount allows access to the amount of rules managed by the manager.
 * Locking: REQUIRES R
 * @return the amount of rules.
 */
Manager::RuleVectorPos Manager::count() const
{
	return m_vRules.size();
}

/**
 * @brief Manager::denyPolicy allows access to the current deny policy.
 * Locking: REQUIRES R
 * @return the current deny policy.
 */
bool Manager::denyPolicy() const
{
	return m_bDenyPolicy;
}

/**
 * @brief Manager::setDenyPolicy sets the deny policy to a given value.
 * Locking: RW
 * @param bDenyPolicy
 */
void Manager::setDenyPolicy(bool bDenyPolicy)
{
	m_oRWLock.lockForWrite();
	if ( m_bDenyPolicy != bDenyPolicy )
	{
		m_bDenyPolicy = bDenyPolicy;
		m_bUnsaved    = true;
	}
	m_oRWLock.unlock();
}

/**
 * @brief Manager::check allows to see whether a rule with the same UUID exists within the
 * manager.
 * Locking: R
 * @param pRule the rule to be verified.
 * @return true if the rule exists within the manager; false otherwise.
 */
bool Manager::check(const Rule* const pRule) const
{
	m_oRWLock.lockForRead();
	bool bReturn = pRule && getUUID( pRule->m_idUUID ) != m_vRules.size();
	m_oRWLock.unlock();

	return bReturn;
}

/**
 * @brief Manager::add adds a rule to the security database.
 * Note: This makes no copy of the rule, so don't delete it after adding.
 * Locking: RW
 * @param pRule: the rule to be added.
 */
void Manager::add(Rule*& pRule)
{
	if ( !pRule ) return;

	QWriteLocker writeLock( &m_oRWLock );

	RuleType::Type     nType   = pRule->type();
	RuleAction::Action nAction = pRule->m_nAction;

	// check for invalid rules
	Q_ASSERT( nType   >  0 && nType   < RuleType::NoOfTypes &&
			  nAction >= 0 && nAction < RuleAction::NoOfActions );
	Q_ASSERT( !pRule->m_idUUID.isNull() );

	RuleVectorPos nExRule = getUUID( pRule->m_idUUID );
	if ( nExRule != m_vRules.size() )
	{
		// we do not allow 2 rules by the same UUID
		remove( nExRule );
	}

	bool bNewAddress = false;
	bool bNewHit	 = false;

	// Special treatment for the different types of rules
	switch ( nType )
	{
	case RuleType::IPAddress:
	{
		uint nIP = qHash( ((IPRule*)pRule)->IP() );
		IPMap::iterator it = m_lmIPs.find( nIP );

		if ( it != m_lmIPs.end() ) // there is a conflicting rule in our map
		{
			pRule->mergeInto( (*it).second );

			delete pRule;
			pRule = NULL;
		}
		else
		{
			m_lmIPs[ nIP ] = (IPRule*)pRule;

			bNewAddress = true;
		}
	}
	break;

	case RuleType::IPAddressRange:
	{
		insertRange( pRule );

		bNewAddress = pRule; // evaluates to false if the previous method sets pRule to NULL
	}
	break;
#if SECURITY_ENABLE_GEOIP
	case RuleType::Country:
	{
		const QString country = pRule->getContentString();
		CountryRuleMap::iterator i = m_lmCountries.find( country );

		if ( i != m_lmCountries.end() ) // there is a conflicting rule in our map
		{
			pRule->mergeInto( (*i).second );

			delete pRule;
			pRule = NULL;
		}
		else
		{
			m_lmCountries[ country ] = (CountryRule*)pRule;

			bNewAddress = true;
		}

		// not all stl implementation guarantee this to have constant time...
		m_bEnableCountries = m_lmCountries.size();
	}
	break;
#endif // SECURITY_ENABLE_GEOIP
	case RuleType::Hash:
	{
		HashVector vHashes = ((HashRule*)pRule)->getHashes();
		RuleVectorPos nPos = getHash( vHashes );

		if ( nPos != m_vRules.size() )
		{
			pRule->mergeInto( m_vRules[nPos] );

			// there is no point on adding a rule for the same content twice,
			// as that content is already blocked.
			delete pRule;
			pRule = NULL;
		}
		else
		{
			// If there isn't a rule for this content or there is a rule for
			// similar but not 100% identical content, add hashes to map.
			foreach ( CHash oHash, vHashes )
			{
				m_lmmHashes.insert( HashPair( qHash( oHash.rawValue() ), (HashRule*)pRule ) );
			}

			bNewHit	= true;
		}
	}
	break;

	case RuleType::RegularExpression:
	{
		const RegExpVectorPos nSize = m_vRegularExpressions.size();

		if ( nSize )
		{
			RegularExpressionRule** pRegExpRules = &m_vRegularExpressions[0];
			for ( RegExpVectorPos i = 0; i < nSize; ++i )
			{
				if ( pRegExpRules[i]->getContentString() == pRule->getContentString() )
				{
					pRule->mergeInto( pRegExpRules[i] );

					delete pRule;
					pRule = NULL;
					break;
				}
			}
		}

		if ( pRule )
		{
			m_vRegularExpressions.push_back( (RegularExpressionRule*)pRule );

			bNewHit	= true;
		}
	}
	break;

	case RuleType::Content:
	{
		const ContentVectorPos nSize = m_vContents.size();

		if ( nSize )
		{
			ContentRule** pContentRules = &m_vContents[0];
			for ( ContentVectorPos i = 0; i < nSize; ++i )
			{
				if ( pContentRules[i]->getContentString() ==  pRule->getContentString() &&
					 pContentRules[i]->getAll()           == ((ContentRule*)pRule)->getAll() )
				{
					pRule->mergeInto( pContentRules[i] );

					delete pRule;
					pRule = NULL;
					break;
				}
			}
		}

		if ( pRule )
		{
			m_vContents.push_back( (ContentRule*)pRule );

			bNewHit	= true;
		}
	}
	break;

	case RuleType::UserAgent:
	{
		const UserAgentVectorPos nSize = m_vUserAgents.size();

		if ( nSize )
		{
			UserAgentRule** pUserAgentRules = &m_vUserAgents[0];
			for ( UserAgentVectorPos i = 0; i < nSize; ++i )
			{
				if ( pUserAgentRules[i]->getContentString() ==  pRule->getContentString() )
				{
					pRule->mergeInto( pUserAgentRules[i] );

					delete pRule;
					pRule = NULL;
					break;
				}
			}
		}

		if ( pRule )
		{
			m_vUserAgents.push_back( (UserAgentRule*)pRule );

			bNewHit	= true;
		}
	}
	break;

	default:
#if SECURITY_ENABLE_GEOIP
		Q_ASSERT( false );
#else
		Q_ASSERT( type == RuleType::Country );
#endif // SECURITY_ENABLE_GEOIP
	}

	m_bUnsaved = true;

	if ( pRule )
	{
		if ( bNewAddress )
		{
			if ( nType == RuleType::IPAddress )
			{
				m_oMissCache.erase( ((IPRule*)pRule)->IP() );
			}
			else
			{
				m_oMissCache.clear();
			}

			m_oMissCache.evaluateUsage();

			m_lqNewAddressRules.push( pRule->getCopy() );
		}
		else if ( bNewHit )		// only add rules related to hit filtering to the queue
		{
			m_lqNewHitRules.push( pRule->getCopy() );
		}

		// add rule to vector containing all rules sorted by GUID
		insert( pRule );

		bool bSave = !pRule->m_bAutomatic;

		// Inform SecurityTableModel about new rule.
		emit ruleAdded( pRule );

		if ( !m_bIsLoading )
		{
			// Unlock mutex before performing system wide security check.
			writeLock.unlock();

			// In case we are currently loading rules from file,
			// this is done uppon completion of the entire process.
			sanityCheck();

			if ( bSave )
				save();
		}
	}
	else
	{
		postLogMessage( LogSeverity::Security,
						tr( "A new security rule has been merged into an existing one." ), false );
	}
}

/**
 * @brief Manager::remove removes a rule from the manager.
 * Reminder: Do not delete the rule after calling this, it will be deleted automatically once the
 * GUI has been updated.
 * Locking: RW
 * @param pRule : the rule
 */
void Manager::remove(const Rule* const pRule)
{
	if ( !pRule )
		return;

	m_oRWLock.lockForWrite();

	remove( getUUID( pRule->m_idUUID ) );

	m_oRWLock.unlock();
}

/**
 * @brief Manager::clear frees all memory and storage containers. Removes all rules.
 * Locking: RW
 */
void Manager::clear()
{
	m_oRWLock.lockForWrite();

	m_lmIPs.clear();
	m_vIPRanges.clear();
#if SECURITY_ENABLE_GEOIP
	m_lmCountries.clear();
#endif // SECURITY_ENABLE_GEOIP
	m_lmmHashes.clear();
	m_vRegularExpressions.clear();
	m_vContents.clear();
	m_vUserAgents.clear();

	qDeleteAll( m_vRules );
	m_vRules.clear();

	qDeleteAll( m_vLoadedAddressRules );
	m_vLoadedAddressRules.clear();

	qDeleteAll( m_vLoadedHitRules );
	m_vLoadedHitRules.clear();

	Rule* pRule = NULL;
	while( m_lqNewAddressRules.size() )
	{
		pRule = m_lqNewAddressRules.front();
		m_lqNewAddressRules.pop();
		delete pRule;
	}

	while ( m_lqNewHitRules.size() )
	{
		pRule = m_lqNewHitRules.front();
		m_lqNewHitRules.pop();
		delete pRule;
	}

	signalQueue.setInterval( m_idRuleExpiry, m_tRuleExpiryInterval );
	m_oMissCache.clear();

	m_bUnsaved = true;

	m_oRWLock.unlock();
}

/**
 * @brief Manager::ban bans a given IP for a specified amount of time.
 * Locking: RW (call to add())
 * @param oAddress : the IP to ban
 * @param nBanLength : the amount of time until the ban shall expire
 * @param bMessage : whether a message shall be posted to the system log
 * @param sComment : comment; if blanc, a default comment is generated depending on nBanLength
 * @param bAutomatic : whether this was an automatic ban by Quazaa
 * @param sSender : string representation of the caller for debugging purposes
 */
void Manager::ban(const QHostAddress& oAddress, RuleTime::Time nBanLength,
				  bool bMessage, const QString& sComment, bool bAutomatic
#ifdef _DEBUG
				  , const QString& sSender
#endif
				  )
{
#ifdef _DEBUG
	if ( oAddress.isNull() )
	{
		Q_ASSERT( false ); // if this happens, make sure to fix the caller... :)
		return;
	}

	qDebug() << "[Security] CSecurity::ban() invoked by: " << sSender.toLocal8Bit().data();
#endif

	const quint32 tNow = common::getTNowUTC();
	IPRule* pIPRule = new IPRule();

	if ( !pIPRule->parseContent( oAddress.toString() ) )
	{
		qDebug() << "[Security] Unable to ban (invalid address): " << oAddress.toString();
		delete pIPRule;
		return;
	}

	pIPRule->m_bAutomatic = bAutomatic;
	pIPRule->setExpiryTime( tNow + nBanLength );
	QString sUntil;

	switch( nBanLength )
	{
	case RuleTime::FiveMinutes:
		pIPRule->m_sComment = tr( "Temp Ignore (5 min)" );
		break;

	case RuleTime::ThirtyMinutes:
		pIPRule->m_sComment = tr( "Temp Ignore (30 min)" );
		break;

	case RuleTime::TwoHours:
		pIPRule->m_sComment = tr( "Temp Ignore (2 h)" );
		break;

	case RuleTime::SixHours:
		pIPRule->m_sComment = tr( "Temp Ignore (2 h)" );
		break;

	case RuleTime::TwelveHours:
		pIPRule->m_sComment = tr( "Temp Ignore (2 h)" );
		break;

	case RuleTime::Day:
		pIPRule->m_sComment = tr( "Temp Ignore (1 d)" );
		break;

	case RuleTime::Week:
		pIPRule->m_sComment = tr( "Client Block (1 week)" );
		break;

	case RuleTime::Month:
		pIPRule->m_sComment = tr( "Quick IP Block (1 month)" );
		break;

	case RuleTime::Session:
		pIPRule->setExpiryTime( RuleTime::Session );
		pIPRule->m_sComment = tr( "Session Ban" );
		sUntil = tr( "until the end of the current session." );
		break;

	case RuleTime::Forever:
		pIPRule->setExpiryTime( RuleTime::Forever );
		pIPRule->m_sComment = tr( "Indefinite Ban" );
		sUntil = tr( "for an indefinite time." );
		break;

	default: // allows for ban lengths not defined in RuleTime::Time
		pIPRule->m_sComment = tr( "Auto Ban" );
	}

	if ( !( sComment.isEmpty() ) )
		pIPRule->m_sComment = sComment;

	Rule* pRule = pIPRule;

	// This also merges any existing rules in case the same IP is added twice.
	add( pRule );

	if ( pRule )
	{
		pRule->count();

		if ( bMessage )
		{
			if ( sUntil.isEmpty() )
				sUntil = tr( "until " ) +
						 QDateTime::fromTime_t( pIPRule->getExpiryTime() ).toString();

			postLogMessage( LogSeverity::Security,
							tr( "Banned %1 %2." ).arg( oAddress.toString(), sUntil ), false );
		}
	}
}

/**
 * @brief Manager::ban bans a given file for a specified amount of time.
 * Locking: R + RW (call to add())
 * @param pHit : the file hit
 * @param nBanLength : the amount of time until the ban shall expire
 * @param nMaxHashes : the maximum amount of hashes to add to the rule
 * @param sComment : comment; if blanc, a default comment is generated depending on nBanLength
 */
void Manager::ban(const CQueryHit* const pHit, RuleTime::Time nBanLength, uint nMaxHashes,
						const QString& sComment)
{
	if ( !pHit || !pHit->isValid() || pHit->m_lHashes.empty() )
	{
		postLogMessage( LogSeverity::Security, tr( "Error: Could not ban invalid file." ), false );
		return;
	}

	m_oRWLock.lockForRead();
	bool bAlreadyBlocked = ( getHash( pHit->m_lHashes ) != m_vRules.size() );
	m_oRWLock.unlock();

	if ( bAlreadyBlocked )
	{
		postLogMessage( LogSeverity::Security,
						tr( "Error: Could not ban already banned file." ), false );
	}
	else
	{
		const quint32 tNow = common::getTNowUTC();
		HashRule* pRule = new HashRule();

		pRule->setExpiryTime( tNow + nBanLength );
		QString sUntil;

		switch( nBanLength )
		{
		case RuleTime::FiveMinutes:
			pRule->m_sComment = tr( "Temp Ignore (5 min)" );
			break;

		case RuleTime::ThirtyMinutes:
			pRule->m_sComment = tr( "Temp Ignore (30 min)" );
			break;

		case RuleTime::TwoHours:
			pRule->m_sComment = tr( "Temp Ignore (2 h)" );
			break;

		case RuleTime::SixHours:
			pRule->m_sComment = tr( "Temp Ignore (2 h)" );
			break;

		case RuleTime::TwelveHours:
			pRule->m_sComment = tr( "Temp Ignore (2 h)" );
			break;

		case RuleTime::Day:
			pRule->m_sComment = tr( "Temp Ignore (1 d)" );
			break;

		case RuleTime::Week:
			pRule->m_sComment = tr( "Client Block (1 week)" );
			break;

		case RuleTime::Month:
			pRule->m_sComment = tr( "Quick Block (1 month)" );
			break;

		case RuleTime::Session:
			pRule->setExpiryTime( RuleTime::Session );
			pRule->m_sComment = tr( "Session Ban" );
			sUntil = tr( "until the end of the current session." );
			break;

		case RuleTime::Forever:
			pRule->setExpiryTime( RuleTime::Forever );
			pRule->m_sComment = tr( "Indefinite Ban" );
			sUntil = tr( "for an indefinite time." );
			break;

		default: // allows for ban lengths not defined in RuleTime::Time
			pRule->m_sComment = tr( "Auto Ban" );
		}

		if ( !( sComment.isEmpty() ) )
			pRule->m_sComment = sComment;

		HashVector hashes;
		hashes.reserve( pHit->m_lHashes.size() );
		foreach( CHash oHash, pHit->m_lHashes )
		{
			hashes.push_back( oHash );
		}

		pRule->setHashes( hashes );
		pRule->reduceByHashPriority( nMaxHashes );

		Rule* pAdd = pRule;
		add( pAdd );

		postLogMessage( LogSeverity::Security,
						tr( "Banned file: " ) + pHit->m_sDescriptiveName, false );
	}
}

/**
 * @brief Manager::isNewlyDenied checks an IP against the list of loaded new security rules.
 * Locking: R
 * @param oAddress : the IP to be checked
 * @return true if the IP is newly banned; false otherwise
 */
bool Manager::isNewlyDenied(const CEndPoint& oAddress)
{
	if ( oAddress.isNull() )
		return false;

	QReadLocker l( &m_oRWLock );

	// This should only be called if new rules have been loaded previously.
	Q_ASSERT( m_bNewRulesLoaded );

	RuleVectorPos n = 0;
	const RuleVectorPos nMax = m_vLoadedAddressRules.size();

	if ( nMax )
	{
		Rule** pRules = &m_vLoadedAddressRules[0];

		while ( n < nMax )
		{
			if ( pRules[n]->match( oAddress ) )
			{
				// the rules are new, so we don't need to check whether they are expired or not
				hit( pRules[n] );

				if ( pRules[n]->m_nAction == RuleAction::Deny )
					return true;
				else if ( pRules[n]->m_nAction == RuleAction::Accept )
					return false;
			}

			++n;
		}
	}

	return false;
}

/**
 * @brief Manager::isNewlyDenied checks a hit against the list of loaded new security rules.
 * Locking: R
 * @param pHit : the QueryHit
 * @param lQuery : the query string
 * @return true if the hit is newly banned; false otherwise
 */
bool Manager::isNewlyDenied(const CQueryHit* const pHit, const QList<QString>& lQuery)
{
	if ( !pHit )
		return false;

	QReadLocker l( &m_oRWLock );

	// This should only be called if new rules have been loaded previously.
	Q_ASSERT( m_bNewRulesLoaded );

	if ( m_vLoadedHitRules.empty() )
		return false;

	RuleVectorPos n = 0;
	const RuleVectorPos nMax = m_vLoadedHitRules.size();

	if ( nMax )
	{
		Rule** pRules = &m_vLoadedHitRules[0];

		while ( n < nMax )
		{
			if ( pRules[n]->match( pHit ) || pRules[n]->match( pHit->m_sDescriptiveName ) ||
				 pRules[n]->match( lQuery, pHit->m_sDescriptiveName ) )
			{
				// the rules are new, so we don't need to check whether they are expired or not
				hit( pRules[n] );

				if ( pRules[n]->m_nAction == RuleAction::Deny )
					return true;
				else if ( pRules[n]->m_nAction == RuleAction::Accept )
					return false;
			}

			++n;
		}
	}

	return false;
}

/**
 * @brief Manager::isDenied checks an IP against the security database.
 * Locking: R
 * @param oAddress : the IP
 * @return true if the IP is denied; false otherwise
 */
bool Manager::isDenied(const CEndPoint& oAddress)
{
	if ( oAddress.isNull() || !oAddress.isValid() )
		return false;

	QReadLocker readLock( &m_oRWLock );

	const quint32 tNow = common::getTNowUTC();

	// First, check the miss cache if the IP is not included in the list of rules.
	// If the address is in cache, it is a miss and no further lookup is needed.
	if ( m_oMissCache.check( oAddress ) )
	{
		if ( m_bLogIPCheckHits )
		{
			postLogMessage( LogSeverity::Security,
							tr( "Skipped repeat IP security check for %s (%i IPs cached)."
								).arg( oAddress.toString(), m_oMissCache.size(), false ), false );
		}

		return m_bDenyPolicy;
	}

	if ( m_bLogIPCheckHits )
	{
		postLogMessage( LogSeverity::Security,
						tr( "Called first-time IP security check for %s."
							).arg( oAddress.toString() ), false );
	}

	// Second, if quazaa local/private blocking is turned on, check if the IP is local/private
	if ( m_bIgnorePrivateIPs )
	{
		if ( isPrivate( oAddress ) )
		{
			postLogMessage( LogSeverity::Security,
							tr( "Local/Private IP denied: %s"
								).arg( oAddress.toString() ), false );
			return true;
		}
	}

	// Third, look up the IP in our country rule map.
#if SECURITY_ENABLE_GEOIP
	if ( m_bEnableCountries )
	{
		CountryRuleMap::const_iterator itCountries;
		itCountries = m_lmCountries.find( oAddress.country() );

		if ( itCountries != m_lmCountries.end() )
		{
			CountryRule* pCountryRule = (*itCountries).second;

			if ( pCountryRule->isExpired( tNow ) )
			{
				expireLater();
			}
			else if ( pCountryRule->match( oAddress ) )
			{
				hit( pCountryRule );

				if ( pCountryRule->m_nAction == RuleAction::Deny )
					return true;
				else if ( pCountryRule->m_nAction == RuleAction::Accept )
					return false;
				else
					Q_ASSERT( pCountryRule->m_nAction == RuleAction::None );
			}
		}
	}
#endif // SECURITY_ENABLE_GEOIP

	// Fourth, check whether the IP is contained within one of the IP range rules.
	{
		const IPRangeVectorPos nPos = findRange( oAddress );
		IPRangeRule* pRangeRule = nPos != m_vIPRanges.size() ? m_vIPRanges[ nPos ] : NULL;

		if ( pRangeRule )
		{
			if ( pRangeRule->isExpired( tNow ) )
			{
				expireLater();
			}
			else
			{
				hit( pRangeRule );

				if ( pRangeRule->m_nAction == RuleAction::Deny )
					return true;
				else if ( pRangeRule->m_nAction == RuleAction::Accept )
					return false;
				else
					Q_ASSERT( pRangeRule->m_nAction == RuleAction::None );
			}
		}
	}

	// Fifth, check the IP rules lookup map.
	{
		IPMap::const_iterator itIPs;
		itIPs = m_lmIPs.find( qHash( oAddress ) );

		if ( itIPs != m_lmIPs.end() )
		{
			IPRule* pIPRule = (*itIPs).second;

			if ( pIPRule->isExpired( tNow ) )
			{
				expireLater();
			}
			else if ( pIPRule->match( oAddress ) )
			{
				if ( pIPRule->m_bAutomatic )
				{
					// Add 30 seconds to the rule time for every hit.
					pIPRule->addExpiryTime( 30 );
				}

				hit( pIPRule );

				if ( pIPRule->m_nAction == RuleAction::Deny )
					return true;
				else if ( pIPRule->m_nAction == RuleAction::Accept )
					return false;
				else
					Q_ASSERT( pIPRule->m_nAction == RuleAction::None );
			}
		}
	}

	// If the IP is not within the rules (and we're using the cache),
	// add the IP to the miss cache.
	m_oMissCache.insert( oAddress, tNow );

	// In this case, return our default policy
	return m_bDenyPolicy;
}

/**
 * @brief Manager::isDenied checks a hit against the security database.
 * Note: This does not verify the hit IP to avoid redundant checking.
 * Locking: R
 * @param pHit : the hit
 * @param lQuery : a list of all search keywords in the same order they have been entered in the
 * edit box of the GUI.
 * @return true if the IP is denied; false otherwise
 */
bool Manager::isDenied(const CQueryHit* const pHit, const QList<QString> &lQuery)
{
	bool bReturn;

	m_oRWLock.lockForRead();
	bReturn = isDenied( pHit ) ||                           // test hashes, file size and extension
			  isDenied( lQuery, pHit->m_sDescriptiveName ); // test regex
	m_oRWLock.unlock();

	return bReturn;
}

/**
 * @brief Manager::isClientBad checks for bad user agents.
 * Note: We don't actually ban these clients, but we don't accept them as a leaf. They are
 * allowed to upload, though.
 * Locking: /
 * @param sUserAgent
 * @return true if the remote computer is running a client that is breaking GPL, causing
 * problems etc.; false otherwise
 */
bool Manager::isClientBad(const QString& sUserAgent) const
{
	// No user agent- assume bad - They allowed to connect but no searches were performed
	if ( sUserAgent.isEmpty() )                 return true;

	QString sSubStr;

	// Bad/old/unapproved versions of Shareaza
	if ( sUserAgent.startsWith( "shareaza", Qt::CaseInsensitive ) )
	{
		sSubStr = sUserAgent.mid( 8 );
		if ( sSubStr.startsWith( " 0."  ) )     return true;
		// There can be some 1.x versions of the real Shareaza but most are fakes
		if ( sSubStr.startsWith( " 1."  ) )     return true;
		// There is also a Shareaza rip-off that identifies as Shareaza 2.0.0.0. Also, the real
		if ( sSubStr.startsWith( " 2.0" ) )     return true; // Shareaza 2.0.0.0 is old and bad.
		if ( sSubStr.startsWith( " 2.1" ) )     return true; // Old version
		if ( sSubStr.startsWith( " 2.2" ) )     return true; // Old version
		if ( sSubStr.startsWith( " 2.3" ) )     return true; // Old version
		if ( sSubStr.startsWith( " 2.4" ) )     return true; // Old version
		if ( sSubStr.startsWith( " 2.5.0" ) )   return true; // Old version
		if ( sSubStr.startsWith( " 3" ) )       return true;
		if ( sSubStr.startsWith( " 6"  ) )      return true;
		if ( sSubStr.startsWith( " 7"  ) )      return true;
		if ( sSubStr.startsWith( " Pro" ) )     return true;

		return false;
	}

	// Dianlei: Shareaza rip-off
	// add only based on alpha code, need verification for others
	if ( sUserAgent.startsWith( "Dianlei", Qt::CaseInsensitive ) )
	{
		sSubStr = sUserAgent.mid( 7 );
		if ( sSubStr.startsWith( " 1." ) )      return true;
		if ( sSubStr.startsWith( " 0." ) )      return true;

		return false;
	}

	// BearShare
	if ( sUserAgent.startsWith( "BearShare", Qt::CaseInsensitive ) )
	{
		sSubStr = sUserAgent.mid( 9 );
		if ( sSubStr.startsWith( " Lite"  ) )   return true;
		if ( sSubStr.startsWith( " Pro"   ) )   return true;
		if ( sSubStr.startsWith( " MP3"   ) )   return true;	// GPL breaker
		if ( sSubStr.startsWith( " Music" ) )   return true;	// GPL breaker
		if ( sSubStr.startsWith( " 6."    ) )   return true;	// iMesh

		return false;
	}

	// Fastload.TV
	if ( sUserAgent.startsWith( "Fastload.TV",            Qt::CaseInsensitive ) ) return true;

	// Fildelarprogram
	if ( sUserAgent.startsWith( "Fildelarprogram",        Qt::CaseInsensitive ) ) return true;

	// Gnutella Turbo (Look into this client some more)
	if ( sUserAgent.startsWith( "Gnutella Turbo",         Qt::CaseInsensitive ) ) return true;

	// Identified Shareaza Leecher Mod
	if ( sUserAgent.startsWith( "eMule mod (4)",          Qt::CaseInsensitive ) ) return true;

	// iMesh
	if ( sUserAgent.startsWith( "iMesh",                  Qt::CaseInsensitive ) ) return true;

	// Mastermax File Sharing
	if ( sUserAgent.startsWith( "Mastermax File Sharing", Qt::CaseInsensitive ) ) return true;

	// Trilix
	if ( sUserAgent.startsWith( "Trilix",                 Qt::CaseInsensitive ) ) return true;

	// Wru (bad GuncDNA based client)
	if ( sUserAgent.startsWith( "Wru",                    Qt::CaseInsensitive ) ) return true;

	// GPL breakers- Clients violating the GPL
	// See http://www.gnu.org/copyleft/gpl.html
	// Some other breakers outside the list

	if ( sUserAgent.startsWith( "C -3.0.1",               Qt::CaseInsensitive ) ) return true;

	// outdated rip-off
	if ( sUserAgent.startsWith( "eTomi",                  Qt::CaseInsensitive ) ) return true;

	// Shareaza rip-off / GPL violator
	if ( sUserAgent.startsWith( "FreeTorrentViewer",      Qt::CaseInsensitive ) ) return true;

	// Is it bad?
	if ( sUserAgent.startsWith( "K-Lite",                 Qt::CaseInsensitive ) ) return true;

	// Leechers, do not allow to connect
	if ( sUserAgent.startsWith( "mxie",                   Qt::CaseInsensitive ) ) return true;

	// ShareZilla (bad Shareaza clone)
	if ( sUserAgent.startsWith( "ShareZilla",             Qt::CaseInsensitive ) ) return true;

	// Shareaza rip-off / GPL violator
	if ( sUserAgent.startsWith( "P2P Rocket",             Qt::CaseInsensitive ) ) return true;

	// Rip-off with bad tweaks
	if ( sUserAgent.startsWith( "SlingerX",               Qt::CaseInsensitive ) ) return true;

	// Not clear why it's bad
	if ( sUserAgent.startsWith( "vagaa",                  Qt::CaseInsensitive ) ) return true;

	if ( sUserAgent.startsWith( "WinMX",                  Qt::CaseInsensitive ) ) return true;

	// Unknown- Assume OK
	return false;
}

/**
 * @brief Manager::isAgentBlocked checks the agent string for banned clients.
 * Locking: R
 * @param sUserAgent : the agent string to be checked
 * @return true for especially bad / leecher clients, as well as user defined agent blocks.
 */
// Test new releases, and remove block if/when they are fixed.
bool Manager::isAgentBlocked(const QString& sUserAgent)
{
	// The remote computer didn't send a "User-Agent", or it sent whitespace
	// We don't like those.
	if ( sUserAgent.isEmpty() )                                         return true;

	// i2hub - leecher client. (Tested, does not upload)
	if ( sUserAgent.startsWith( "i2hub 2.0", Qt::CaseInsensitive ) )    return true;

	// foxy - leecher client. (Tested, does not upload)
	// having something like Authentication which is not defined on specification
	if ( sUserAgent.startsWith( "foxy", Qt::CaseInsensitive ) )         return true;

	// Check by content filter
	m_oRWLock.lockForRead();
	bool bReturn = isAgentDenied( sUserAgent );
	m_oRWLock.unlock();

	return bReturn;
}

/**
 * @brief Manager::isVendorBlocked checks for blocked vendors.
 * Locking: /
 * @param sVendor
 * @return true for blocked vendors; false otherwise
 */
bool Manager::isVendorBlocked(const QString& sVendor) const
{
	// foxy - leecher client. (Tested, does not upload)
	// having something like Authentication which is not defined on specification
	if ( sVendor.startsWith( "foxy", Qt::CaseInsensitive ) )
		return true;

	// Allow it
	return false;
}

/**
 * @brief Manager::start starts the Security Manager.
 * Initializes signal/slot connections, pulls settings and sets up cleanup interval counters.
 * Locking: RW
 * @return true if loading the rules was successful; false otherwise
 */
bool Manager::start()
{
	// Register SharedRulePtr to allow using this type with queued signal/slot connections.
	qRegisterMetaType< SharedRulePtr >( "SharedRulePtr" );
	qRegisterMetaType< ID >( "ID" );


	connect( &quazaaSettings, SIGNAL( securitySettingsChanged() ),
			 &securitySettigs, SLOT( settingsChanged() ), Qt::QueuedConnection );

	connect( &securitySettigs, SIGNAL( settingsUpdate() ), SLOT( settingsChanged() ) );

	// Pull settings from global database to local copy.
	settingsChanged();

	// Set up interval timed cleanup operations.
	m_idRuleExpiry      = signalQueue.push( this, "expire", m_tRuleExpiryInterval, true );

	loadPrivates();

	return load(); // Load security rules from HDD.
}

/**
 * @brief Manager::stop prepares the security manager for destruction.
 * Saves the rules to disk, disonnects signal/slot connections, frees memory
 * and clears up storage containers.
 * Locking: RW
 * @return true if saving was successful; false otherwise
 */
bool Manager::stop()
{
	signalQueue.pop( this );    // Remove all cleanup intervall timers from the queue.

	disconnect( &quazaaSettings, SIGNAL( securitySettingsChanged() ),
				this, SLOT( settingsChanged() ) );

	bool bSaved = save( true ); // Save security rules to disk.
	clear();                    // Release memory and free containers.

	return bSaved;
}

/**
 * @brief Manager::load loads the rule database from the HDD.
 * Locking: RW
 * @return true if successful; false otherwise
 */
bool Manager::load()
{
	// TODO: move this to externals.h
	QString sPath = dataPath();

	if ( load( sPath + "security.dat" ) )
	{
		return true;
	}
	else
	{
		// try backup file if primary file failed for some reason
		if ( load( sPath + "security_backup.dat" ) )
		{
			return true;
		}

		// fall back to default file if neither primary nor backup file exists
		sPath = QDir::toNativeSeparators( QString( "%1/DefaultSecurity.dat"
												   ).arg( qApp->applicationDirPath() ) );
		return load( sPath );
	}
}

/**
 * @brief Manager::save writes the security rules to HDD.
 * Skips saving if there haven't been any important changes and bForceSaving is not set to true.
 * Locking: R
 * @param bForceSaving : use this to prevent the manager from taking the decision that saving
 * isn't needed ATM
 * @return true if saving has been successfull/saving has been skipped; false otherwise
 */
bool Manager::save(bool bForceSaving) const
{
	if ( !m_bUnsaved && !bForceSaving )
	{
		return true;		// Saving not required ATM.
	}

	const QString sPath = dataPath();

	m_oRWLock.lockForRead();
	m_bUnsaved   = false;
	bool bReturn = common::securedSaveFile( sPath, "security.dat", Components::Security,
											this, &Security::Manager::writeToFile );
	m_oRWLock.unlock();

	return bReturn;
}

/**
 * @brief Manager::writeToFile is a helper method required for save().
 * Locking: REQUIRES R
 * @param pManager : the security manager
 * @param oFile : the file to be written to
 * @return the number of rules written to file
 */
quint32 Manager::writeToFile(const void * const pManager, QFile& oFile)
{
	quint16 nVersion = SECURITY_CODE_VERSION;

	QDataStream oStream( &oFile );
	Manager* pSManager = (Manager*)pManager;

	oStream << nVersion;
	oStream << pSManager->m_bDenyPolicy;
	oStream << pSManager->count();

	const RuleVectorPos nSize = pSManager->m_vRules.size();

	if ( nSize )
	{
		Rule** pRules = &(pSManager->m_vRules)[0];
		for ( RuleVectorPos n = 0; n < nSize; ++n )
		{
			Rule::save( pRules[n], oStream );
		}
	}

	return (quint32)pSManager->count();
}

/**
 * @brief Manager::import imports a security file with unknown format located at sPath.
 * Locking: RW
 * @param sPath : the location
 * @return true on success; false otherwise
 */
bool Manager::import(const QString& sPath)
{
	if ( fromXML( sPath ) || fromP2P( sPath ) )
	{
		sanityCheck();
		return true;
	}
	else
	{
		return false;
	}
}

/**
 * @brief Manager::fromP2P imports a P2P rule file into the manager.
 * Locking: RW
 * @param sPath : the file location
 * @return true if successful; false otherwise
 */
bool Manager::fromP2P(const QString& sPath)
{
	QFile file(sPath);

	if ( !file.open( QIODevice::ReadOnly | QIODevice::Text ) )
		return false;

	emit updateLoadMax(file.size());

	quint8 nGuiThrottle = 0;
	uint   nCount       = 0;

	m_oRWLock.lockForWrite();
	m_bIsLoading = true;
	m_oRWLock.unlock();

	QTextStream fsImport( &file );
	while ( !fsImport.atEnd() )
	{
		const QString sLine = fsImport.readLine();
		emit updateLoadProgress( fsImport.pos() );

		if ( !sLine.isEmpty() && !sLine.startsWith( "#" ) && sLine.contains( ":" ) )
		{
			QStringList lArguments = sLine.split( ":" );
			QString     sComment   = lArguments.at(0);
			QString     sContent   = lArguments.at(1);
			Rule* pRule;

			QStringList lAddresses = sContent.split( "-" );

			if ( lAddresses.at(0) == lAddresses.at(1) )
			{
				sContent = lAddresses.at(0);
				pRule = new IPRule();
			}
			else
			{
				pRule = new IPRangeRule();
			}

			if ( !pRule->parseContent( sContent ) )
				break;

			pRule->m_sComment   = sComment;
			pRule->m_nAction    = RuleAction::Deny;
			pRule->setExpiryTime( RuleTime::Forever );
			pRule->m_bAutomatic = false;

			add( pRule );

			nCount += pRule ? 1 : 0;
		}

		++nGuiThrottle;
		if ( nGuiThrottle == 50 )
		{
			// prevent GUI from becoming unresponsive
			qApp->processEvents( QEventLoop::ExcludeUserInputEvents, 50 );
			nGuiThrottle = 0;
		}
	}

	m_oRWLock.lockForWrite();
	m_bIsLoading = false;
	m_oRWLock.unlock();

	sanityCheck();
	save();

	return nCount;
}

/**
 * @brief Manager::xmlns contains the xml file schema specification.
 */
const QString Manager::xmlns = "http://www.shareaza.com/schemas/Security.xsd";

/**
 * @brief Manager::fromXML imports rules from an XML file.
 * Locking: RW
 * @param sPath : the path to the XML file.
 * @return true if at least one rule could be imported; false otherwise
 */
bool Manager::fromXML(const QString& sPath)
{
	QFile oFile( sPath );
	if ( !oFile.open( QIODevice::ReadOnly ) )
		return false;

	QXmlStreamReader xmlDocument( &oFile );

	if ( xmlDocument.atEnd() ||
		!xmlDocument.readNextStartElement() ||
		 xmlDocument.name().toString().compare( "security", Qt::CaseInsensitive ) )
		return false;

	postLogMessage( LogSeverity::Information,
					tr( "Importing security rules from file: " ) + sPath, false );

	float nVersion;

	QXmlStreamAttributes attributes = xmlDocument.attributes();
	{
		bool bOK;
		QString sVersion;

		// attributes.value() returns an empty StringRef if the attribute "version" is not present.
		// In that case the conversion to float fails and version is set to 1.0.
		sVersion = attributes.value( "version" ).toString();
		nVersion = sVersion.toFloat( &bOK );
		if ( !bOK )
		{
			postLogMessage( LogSeverity::Error,
							tr( "Failed to read the Security XML version number from file." ),
							false );
			nVersion = 1.0;
		}
	}

	const quint32 tNow = common::getTNowUTC();

	m_oRWLock.lockForWrite();
	m_bIsLoading = true;
	m_oRWLock.unlock();

	Rule* pRule = NULL;
	uint nRuleCount = 0;

	// For all rules do:
	while ( !xmlDocument.atEnd() )
	{
		// Go forward until the beginning of the next rule
		xmlDocument.readNextStartElement();

		// Verify whether it's a rule
		if ( xmlDocument.name().toString().compare( "rule", Qt::CaseInsensitive ) )
		{
			// Parse it
			pRule = Rule::fromXML( xmlDocument, nVersion );

			if ( pRule )
			{
				if ( !pRule->isExpired( tNow ) )
				{
					add( pRule );
				}
				else
				{
					delete pRule;
				}
				pRule = NULL;
				++nRuleCount;
			}
			else
			{
				postLogMessage( LogSeverity::Error,
								tr( "Failed to read a Security Rule from XML." ),
								false );
			}
		}
		else
		{
			postLogMessage( LogSeverity::Error,
							tr( "Unrecognized entry in XML file with name: " ) +
							xmlDocument.name().toString(),
							false );
		}

		// prevent GUI from becoming unresponsive
		qApp->processEvents(QEventLoop::ExcludeUserInputEvents, 50);
	}

	m_oRWLock.lockForWrite();
	m_bIsLoading = false;
	m_oRWLock.unlock();

	sanityCheck();
	save();

	postLogMessage( LogSeverity::Information,
					QString::number( nRuleCount ) + tr( " Rules imported." ),
					false );

	return nRuleCount;
}

/**
 * @brief Manager::toXML exports all rules to an XML file.
 * Locking: R
 * @param sPath : the path to the new rules file
 * @return true if successful; false otherwise
 */
bool Manager::toXML(const QString& sPath) const
{
	QFile oFile( sPath );
	if( !oFile.open( QIODevice::ReadWrite ) )
		return false;

	QXmlStreamWriter xmlDocument( &oFile );

	xmlDocument.writeStartElement( xmlns, "security" );
	xmlDocument.writeAttribute( "version", "2.0" );

	m_oRWLock.lockForRead();

	const RuleVectorPos nSize = m_vRules.size();

	if ( nSize )
	{
		Rule* const * pRules = &m_vRules[0];
		for ( RuleVectorPos n = 0; n < nSize ; ++n )
		{
			pRules[n]->toXML( xmlDocument );
		}
	}

	m_oRWLock.unlock();

	xmlDocument.writeEndElement();

	return true;
}

/**
 * @brief Manager::receivers returns the number of listeners to a given signal of the manager.
 * Note that this is a method that violates the modularity principle.
 * Plz don't use it if you've got a problem with that(for example because of religious reasons).
 * Locking: /
 * @param signal : the signal
 * @return the number of listeners
 */
/*int Manager::receivers(const char* signal) const
{
	return QObject::receivers( signal );
}*/

/**
 * @brief ruleInfoRunning allows to know whether anyone is listening to the ruleInfo signal.
 * Locking: /
 * @return true if somebody is listening to the ruleInfo signal; false otherwise.
 */
bool Manager::ruleInfoRunning()
{
	return QObject::receivers( SIGNAL( ruleInfo( Rule* ) ) );
}

/**
 * @brief Manager::emitUpdate emits a ruleUpdated signal for a given RuleGUIID nID.
 * Locking: /
 * @param nID : the ID
 */
void Manager::emitUpdate(ID nID)
{
	emit ruleUpdated( nID );
}

/**
 * @brief Manager::requestRuleList allows to request ruleInfo() signals for all rules.
 * Qt slot. Triggers the Security Manager to emit all rules using the ruleInfo() signal.
 * Locking: R
 */
void Manager::requestRuleInfo()
{
	m_oRWLock.lockForRead();

	const RuleVectorPos nSize = m_vRules.size();

	if ( nSize )
	{
		Rule** pRules = &m_vRules[0];
		for ( RuleVectorPos n = 0; n < nSize ; ++n )
		{
			emit ruleInfo( pRules[n] );
		}
	}

	m_oRWLock.unlock();
}

/**
 * @brief Manager::sanityCheck initializes a system wide sanity check.
 * Qt slot. Triggers a system wide sanity check.
 * The sanity check is delayed by 5s, if a write lock couldn't be aquired after 200ms.
 * The sanity check is aborted if it takes longer than 2min to finish.
 * Locking: RW
 */
void Manager::sanityCheck()
{
	if ( m_oRWLock.tryLockForWrite( 200 ) )
	{
		// This indicates that an error happend previously.
		Q_ASSERT( m_bNewRulesLoaded || m_vLoadedAddressRules.empty() && m_vLoadedHitRules.empty() );

		// Check whether there are new rules to deal with.
		bool bNewRules = m_lqNewAddressRules.size() || m_lqNewHitRules.size();

		if ( bNewRules )
		{
			if ( !m_bNewRulesLoaded )
			{
				loadNewRules();

				// Count how many "OK"s we need to get back.
				m_nPendingOperations = receivers( SIGNAL( performSanityCheck() ) );

				// if there is anyone listening, start the sanity check
				if ( m_nPendingOperations )
				{
#ifdef _DEBUG
					// Failsafe mechanism in case there are massive problems somewhere else.
					m_idForceEoSC = signalQueue.push( this, "forceEndOfSanityCheck", 120 );
#endif

					// Inform all other modules aber the necessity of a sanity check.
					emit performSanityCheck();
				}
				else
				{
					clearNewRules();
				}
			}
			else // other sanity check still in progress
			{
				// try again later
				signalQueue.push( this, "sanityCheck", 5 );
			}
		}

		m_oRWLock.unlock();
	}
	else // We didn't get a write lock in a timely manner.
	{
		// try again later
		signalQueue.push( this, "sanityCheck", 5 );
	}
}

/**
 * @brief Manager::sanityCheckPerformed
 * Qt slot. Must be notified by all listeners to the signal performSanityCheck() once they have
 * completed their work.
 * Locking: RW
 */
void Manager::sanityCheckPerformed()
{
	m_oRWLock.lockForWrite();

	Q_ASSERT( m_bNewRulesLoaded );        // TODO: remove after testing
	Q_ASSERT( m_nPendingOperations > 0 );

	if ( --m_nPendingOperations == 0 )
	{
		postLogMessage( LogSeverity::Debug, QObject::tr( "Sanity Check finished successfully. " ) +
				 QObject::tr( "Starting cleanup now." ), true );

		clearNewRules();
	}
	else
	{
		postLogMessage( LogSeverity::Debug, QObject::tr( "A component finished with sanity checking. " ) +
				 QObject::tr( "Still waiting for %s other components to finish."
							  ).arg( m_nPendingOperations ), true );
	}

	m_oRWLock.unlock();
}

#ifdef _DEBUG
/**
 * @brief CSecurity::forceEndOfSanityCheck
 * Qt slot. Aborts the currently running sanity check by clearing its rule lists.
 * For use in debug version only.
 * Locking: RW
 */
void Manager::forceEndOfSanityCheck()
{
	m_oRWLock.lockForWrite();
#ifdef _DEBUG
	if ( m_nPendingOperations )
	{
		QString sTmp = QObject::tr( "Sanity check aborted. Most probable reason: It took some " ) +
					   QObject::tr( "component longer than 2min to call sanityCheckPerformed() " ) +
					   QObject::tr( "after having recieved the signal performSanityCheck()." );
		postLogMessage( LogSeverity::Error, sTmp, true );
		Q_ASSERT( false );
	}
#endif //_DEBUG

	clearNewRules();
	m_nPendingOperations = 0;
	m_oRWLock.unlock();
}
#endif //_DEBUG

/**
 * @brief Manager::expire removes rules that have reached their expiration date.
 * Qt slot. Checks the security database for expired rules.
 * Locking: RW
 */
void Manager::expire()
{
	postLogMessage( LogSeverity::Debug, QString( "Expiring old rules now!" ), true );

	m_oRWLock.lockForWrite();

	quint16 nCount  = 0;
	const RuleVectorPos nSize = m_vRules.size();

	if ( nSize )
	{
		const quint32 tNow = common::getTNowUTC();

		Rule** pRules   = &m_vRules[0];
		RuleVectorPos n = nSize;

		while ( n > 0 )
		{
			--n;

			if ( pRules[n]->isExpired( tNow ) )
			{
				remove( n );
				++nCount;
			}
		}
	}

	m_bExpiryRequested = false;

	m_oRWLock.unlock();

	postLogMessage( LogSeverity::Debug, QString::number( nCount ) + " Rules expired.", true );
}

/**
 * @brief Manager::settingsChanged needs to be triggered on setting changes.
 * Qt slot. Pulls all relevant settings from securitySettings
 * and refreshes all components depending on them.
 * Locking: RW
 */
void Manager::settingsChanged()
{
	m_oRWLock.lockForWrite();
	securitySettigs.m_oLock.lock();

	if ( m_tRuleExpiryInterval != securitySettigs.m_tRuleExpiryInterval )
	{
		m_tRuleExpiryInterval = securitySettigs.m_tRuleExpiryInterval;
		signalQueue.setInterval( m_idRuleExpiry, m_tRuleExpiryInterval );
	}

	m_bLogIPCheckHits   = securitySettigs.m_bLogIPCheckHits;
	m_bIgnorePrivateIPs = securitySettigs.m_bIgnorePrivateIPs;

	securitySettigs.m_oLock.unlock();
	m_oRWLock.unlock();
}

/**
 * @brief Manager::hit increases the rule counters and emits an updating signal to the GUI.
 * Locking: /
 * @param pRule : the rule that has been hit
 */
void Manager::hit(Rule* pRule)
{
	pRule->count();
	emit ruleUpdated( pRule->m_nGUIID );
}

/**
 * @brief Manager::loadNewRules loads waiting rules into the containers used for sanity
 * checking.
 * Locking: REQUIRES RW
 */
void Manager::loadNewRules()
{
	Q_ASSERT( !m_bNewRulesLoaded );

	// should both be empty
	Q_ASSERT( !( m_vLoadedAddressRules.size() || m_vLoadedHitRules.size() ) );

	// there should be at least 1 new rule
	Q_ASSERT( m_lqNewAddressRules.size() || m_lqNewHitRules.size() );

	Rule* pRule = NULL;

	while ( m_lqNewAddressRules.size() )
	{
		pRule = m_lqNewAddressRules.front();
		m_lqNewAddressRules.pop();

		// Only IP, IP range and coutry rules are allowed.
		Q_ASSERT( pRule->type() && pRule->type() < 4 );

		m_vLoadedAddressRules.push_back( pRule );

		pRule = NULL;
	}

	while ( m_lqNewHitRules.size() )
	{
		pRule = m_lqNewHitRules.front();
		m_lqNewHitRules.pop();

		// Only hit related rules are allowed.
		Q_ASSERT( pRule->type() > 3 );

		m_vLoadedHitRules.push_back( pRule );

		pRule = NULL;
	}

	m_bNewRulesLoaded = true;
}

/**
 * @brief Manager::clearNewRules unloads new rules from sanity check containers.
 * Locking: REQUIRES RW
 */
void Manager::clearNewRules()
{
	Q_ASSERT( m_bNewRulesLoaded );

	// There should at least be one rule.
	Q_ASSERT( m_vLoadedAddressRules.size() || m_vLoadedHitRules.size() );

	RuleVectorPos n = 0, nSize = m_vLoadedAddressRules.size();

	if ( nSize )
	{
		Rule** pLoadedAddressRules = &m_vLoadedAddressRules[0];
		while ( n < nSize )
		{
			delete pLoadedAddressRules[n];
		}
	}

	m_vLoadedAddressRules.clear();

	n = 0;
	nSize = m_vLoadedHitRules.size();

	if ( nSize )
	{
		Rule** pLoadedHitRules = &m_vLoadedHitRules[0];
		while ( n < nSize )
		{
			delete pLoadedHitRules[n];
		}
	}

	m_vLoadedHitRules.clear();

#ifdef _DEBUG // use failsafe to abort sanity check only in debug version
	if ( !m_idForceEoSC.isNull() )
	{
		Q_ASSERT( signalQueue.pop( m_idForceEoSC ) );
		m_idForceEoSC = QUuid();
	}
#endif

	m_bNewRulesLoaded = false;
}

/**
 * @brief Manager::loadPrivates loads the private IP renges into the appropriate container.
 * Locking RW
 */
void Manager::loadPrivates()
{
	m_oRWLock.lockForWrite();

	clearPrivates();

	m_vPrivateRanges.reserve( 12 );

	std::vector<QString> vRanges;
	vRanges.reserve( 12 );

	vRanges.push_back( QString(      "0.0.0.0-0.255.255.255"   ) );
	vRanges.push_back( QString(     "10.0.0.0-10.255.255.255"  ) );
	vRanges.push_back( QString(   "100.64.0.0-100.127.255.255" ) );
	vRanges.push_back( QString(    "127.0.0.0-127.255.255.255" ) );
	vRanges.push_back( QString(  "169.254.0.0-169.254.255.255" ) );
	vRanges.push_back( QString(   "172.16.0.0-172.31.255.255"  ) );
	vRanges.push_back( QString(    "192.0.0.0-192.0.2.255"     ) );
	vRanges.push_back( QString(  "192.168.0.0-192.168.255.255" ) );
	vRanges.push_back( QString(   "198.18.0.0-198.19.255.255"  ) );
	vRanges.push_back( QString( "198.51.100.0-198.51.100.255"  ) );
	vRanges.push_back( QString(  "203.0.113.0-203.0.113.255"   ) );
	vRanges.push_back( QString(    "240.0.0.0-255.255.255.255" ) );

	QString*     pRanges = &vRanges[0];
	IPRangeRule* pRule   = NULL;

	for ( uchar n = 0; n < 12; ++n )
	{
		pRule = new IPRangeRule();
		pRule->parseContent( pRanges[n] );
		m_vPrivateRanges.push_back( pRule );
		pRule = NULL;
	}

	m_oRWLock.unlock();
}

/**
 * @brief Manager::clearPrivates clears the private rules from the respective container.
 */
void Manager::clearPrivates()
{
	const IPRangeVectorPos nSize =  m_vPrivateRanges.size();

	if ( nSize )
	{
		IPRangeRule** pRule = &m_vPrivateRanges[0];
		IPRangeVectorPos n = 0;

		while ( n < nSize )
		{
			delete pRule[n];
		}
	}

	m_vPrivateRanges.clear();
}

/**
 * @brief Manager::load loads rules from HDD file into manager.
 * Locking: RW
 * @param sPath : the location of the rule file on disk
 * @return true if loading was successful; false otherwise
 */
bool Manager::load( QString sPath )
{
	QFile oFile( sPath );

	if ( ! oFile.open( QIODevice::ReadOnly ) )
		return false;

	Rule* pRule = NULL;

	// TODO : handle changes in storage format

	try
	{
		clear();

		QDataStream fsFile( &oFile );

		quint16 nVersion;
		fsFile >> nVersion;

		bool bDenyPolicy;
		fsFile >> bDenyPolicy;

		quint32 nCount;
		fsFile >> nCount;

		const quint32 tNow = common::getTNowUTC();

		m_oRWLock.lockForWrite();
		m_bDenyPolicy = bDenyPolicy;
		m_bIsLoading  = true; // Prevents sanity check from being executed at each add() operation.
		m_vRules.reserve( 2 * nCount ); // prevent unneccessary reallocations of the vector...
		m_oRWLock.unlock();

		int nSuccessCount = 0;

		if ( nVersion >= 2 )
		{
			while ( nCount > 0 )
			{
				Rule::load( pRule, fsFile, nVersion );

				if ( pRule->isExpired( tNow, true ) )
				{
					delete pRule;
				}
				else
				{
					add( pRule );
					nSuccessCount += pRule ? 1 : 0;
				}

				pRule = NULL;

				nCount--;
			}
		}

		m_oRWLock.lockForWrite();
		m_bIsLoading = false;
		m_oRWLock.unlock();

		if ( nSuccessCount )
		{
			postLogMessage( LogSeverity::Debug, QObject::tr( "Loaded security rules from file: %1"
															 ).arg( sPath ), false );
			postLogMessage( LogSeverity::Debug, QObject::tr( "Loaded %1 rules."
															 ).arg( nSuccessCount ), false );
		}

		// If necessary perform sanity check after loading.
		sanityCheck();

		// Saving not required here. No rules have been changed
	}
	catch ( ... )
	{
		if ( pRule )
			delete pRule;

		clear();

		m_oRWLock.lockForWrite();
		m_bIsLoading = false;
		m_oRWLock.unlock();

		return false;
	}
	oFile.close();

	return true;
}

/**
 * @brief Manager::insert inserts a new rule at the correct place into the rules vector.
 * Locking: REQUIRES RW
 * @param pRule : the rule to be inserted
 */
void Manager::insert(Rule* pRule)
{
	RuleVectorPos nPos = m_vRules.size();
	m_vRules.push_back( NULL );

	Rule** pArray = &m_vRules[0]; // access internal array

	while ( nPos > 0 && pRule->m_idUUID < pArray[nPos - 1]->m_idUUID )
	{
		pArray[nPos] = pArray[--nPos];
	}

	pArray[nPos] = pRule;
}

/**
 * @brief Manager::erase removes the rule at the position nPos from the vector.
 * Locking: REQUIRES RW
 * @param nPos : the position
 */
void Manager::erase(RuleVectorPos nPos)
{
	Q_ASSERT( nPos >= 0 && nPos < m_vRules.size() );

	const RuleVectorPos nMax = m_vRules.size() - 1;

	Rule** pArray = &m_vRules[0]; // access internal array
	delete pArray[nPos];          // delete rule

	RuleVectorPos i = nPos;
	while ( i < nMax )            // move all other elements 1 pos up the latter
	{
		pArray[i] = pArray[++i];
	}

	m_vRules.pop_back();          // remove last element
}                                 // (either the deleted one or a copy of the one next to it)

/**
 * @brief Manager::insertRange inserts a range rule into the respective container.
 * Locking: REQUIRES RW
 * @param pNewRange : the range rule
 */
void Manager::insertRange(Rule*& pNew)
{
	Rule*            pRule = NULL;
	IPRangeRule* pNewRange = (IPRangeRule*)pNew;
	IPRangeVectorPos  nPos = findRange( pNewRange->startIP() );

	if ( nPos != m_vIPRanges.size() )
	{
		pRule = m_vIPRanges[nPos++]->merge( pNewRange );

		if ( pNewRange )
		{
			while ( nPos < m_vIPRanges.size() && m_vIPRanges[nPos]->endIP() < pNewRange->endIP() )
			{
				postLogMessage( LogSeverity::Security,
								QString( "Merging. Removing overlapping IP range %1-%2."
										 ).arg( m_vIPRanges[nPos]->startIP().toString(),
												m_vIPRanges[nPos]->endIP().toString() ), false );
				remove( getUUID( m_vIPRanges[nPos]->m_idUUID ) );

			}

			if ( nPos < m_vIPRanges.size() && m_vIPRanges[nPos]->startIP() < pNewRange->endIP() )
			{
				m_vIPRanges[nPos]->merge( pNewRange );
			}
		}
	}

	if ( pNewRange )
		insertRangeHelper( pNewRange );

	if ( pRule )
		insertRange( pRule );

	pNew = pNewRange; // Make sure that pNewRange being set to NULL is reported back.

#ifdef _DEBUG
	int n = 0, nSize = (int)m_vIPRanges.size() - 1;
	if ( nSize >= 0 )
	{
		IPRangeRule** pRules = &m_vIPRanges[0];
		while ( n < nSize )
		{
			Q_ASSERT( pRules[ n ]->startIP() < pRules[ n ]->endIP()   );
			Q_ASSERT( pRules[ n ]->endIP()   < pRules[n+1]->startIP() );
			Q_ASSERT( pRules[n+1]->startIP() < pRules[n+1]->endIP()   );
		}
	}
#endif
}

/**
 * @brief Manager::insertRangeHelper inserts a range rule at the correct place into the vector.
 * Locking: REQUIRES RW
 * @param pNewRange : the range rule
 */
void Manager::insertRangeHelper(IPRangeRule* pNewRange)
{
	IPRangeVectorPos nPos = m_vIPRanges.size();
	m_vIPRanges.push_back( NULL );

	IPRangeRule** pArray = &m_vIPRanges[0]; // access internal array

	while ( nPos > 0 && pNewRange->m_idUUID < pArray[nPos - 1]->m_idUUID )
	{
		pArray[nPos] = pArray[--nPos];
	}

	pArray[nPos] = pNewRange;
}

/*{
	IPRangeRule* pNewRule = ((IPRangeRule*)pRule);
	IPRangeRule* pOldRule = findRange(pNewRule->startIP());

	if(!pOldRule)
		pOldRule = findRange(pNewRule->endIP());

	if(pOldRule)
	{
		// fix range conflicts with old rules
		if((pNewRule->m_nAction == Rule::srDeny && pOldRule->m_nAction == Rule::srDeny) ||
		   (pNewRule->m_nAction == Rule::srAccept && pOldRule->m_nAction == Rule::srAccept)) {
			if( pNewRule->startIP() == pOldRule->startIP() && pNewRule->endIP() == pOldRule->endIP()  )
			{
				systemLog.postLogMessage(LogSeverity::Security, QString("New IP range rule is the same as old rule %3-%4, skipping.")
								  .arg(pOldRule->startIP().toString())
								  .arg(pOldRule->endIP().toString()) );

				delete pRule;
				pRule = NULL;
				return;
			}
			else if( pOldRule->startIP() < pNewRule->startIP() && pOldRule->endIP() > pNewRule->endIP() )
			{
				systemLog.postLogMessage(LogSeverity::Security, QString("Old IP range rule %1-%2 encompasses new rule %3-%4, skipping.")
								  .arg(pNewRule->startIP().toString())
								  .arg(pNewRule->endIP().toString())
								  .arg(pOldRule->startIP().toString())
								  .arg(pOldRule->endIP().toString()) );

				delete pRule;
				pRule = NULL;
				return;
			}
			else if( pNewRule->startIP() < pOldRule->startIP() && pNewRule->endIP() > pOldRule->endIP()  )
			{
				systemLog.postLogMessage(LogSeverity::Security, QString("New IP range rule %1-%2 encompasses old rule %3-%4, replacing.")
								  .arg(pNewRule->startIP().toString())
								  .arg(pNewRule->endIP().toString())
								  .arg(pOldRule->startIP().toString())
								  .arg(pOldRule->endIP().toString()) );

				//remove( pOldRule, false );
			} else {
				bool bMatch = false;
				if( pNewRule->contains( pOldRule->startIP() ) )
				{
					systemLog.postLogMessage(LogSeverity::Security, QString("Old IP range rule start IP %1 is within new rule %2-%3, merging.")
									  .arg(pOldRule->startIP().toString())
									  .arg(pNewRule->startIP().toString())
									  .arg(pNewRule->endIP().toString()) );

					bMatch = true;
					pNewRule->parseContent(QString("%1-%2").arg(pNewRule->startIP().toString()).arg(pOldRule->endIP().toString()));
				}
				if( pNewRule->contains( pOldRule->endIP() ) )
				{
					systemLog.postLogMessage(LogSeverity::Security, QString("Old IP range rule end IP %1 is within new rule %2-%3, merging.")
									  .arg(pOldRule->endIP().toString())
									  .arg(pNewRule->startIP().toString())
									  .arg(pNewRule->endIP().toString()) );

					bMatch = true;
					pNewRule->parseContent(QString("%1-%2").arg(pOldRule->startIP().toString()).arg(pNewRule->endIP().toString()));
				}


				//if(bMatch)
					//remove( pOldRule, false );
			}
		}
	}
}*/

/**
 * @brief Manager::erase removes the rule at the position nPos from the IP ranges vector.
 * Locking: REQUIRES RW
 * @param nPos : the position
 */
void Manager::eraseRange(Manager::RuleVectorPos nPos)
{
	Q_ASSERT( nPos >= 0 && nPos < m_vIPRanges.size() );

	const RuleVectorPos nMax = m_vIPRanges.size() - 1;

	Rule** pArray = &m_vRules[0]; // access internal array
	delete pArray[nPos];          // delete rule

	RuleVectorPos i = nPos;
	while ( i < nMax )            // move all other elements 1 pos up the latter
	{
		pArray[i] = pArray[++i];
	}

	m_vRules.pop_back();          // remove last element
}                                 // (either the deleted one or a copy of the one next to it)

/**
 * @brief Manager::getUUID returns the rule position for the given UUID.
 * Note that there is always max one rule per UUID.
 * Locking: REQUIRES R
 * @param idUUID : the UUID
 * @return the rule position
 */
Manager::RuleVectorPos Manager::getUUID(const QUuid& idUUID) const
{
	const RuleVectorPos nSize = m_vRules.size();

	if ( m_vRules.empty() || idUUID.isNull() )
	{
		return nSize;
	}

	Rule* const * pRules = &m_vRules[0];

	RuleVectorPos nMiddle, nHalf, nBegin = 0;
	RuleVectorPos n = nSize - nBegin;

	while ( n > 0 )
	{
		nHalf = n >> 1;

		nMiddle = nBegin + nHalf;

		if ( idUUID < pRules[nMiddle]->m_idUUID )
		{
			n = nHalf;
		}
		else
		{
			if ( idUUID == pRules[nMiddle]->m_idUUID )
			{
				return nMiddle;
			}

			nBegin = nMiddle + 1;
			n -= nHalf + 1;
		}
	}

	return nSize;
}

/**
 * @brief Manager::getHash
 * Note: this returns the first rule found. There might be others, however.
 * Locking: REQUIRES R
 * @param hashes : a vector of hashes to look for
 * @return the rule position
 */
Manager::RuleVectorPos Manager::getHash(const HashVector& hashes) const
{
	// We are not searching for any hash. :)
	if ( hashes.empty() )
		return m_vRules.size();

	std::pair<HashIterator, HashIterator> oBounds;

	// For each hash that has been given to the function:
	foreach ( CHash oHash, hashes )
	{
		// 1. Check whether a corresponding rule can be found in our lookup container.
		oBounds = m_lmmHashes.equal_range( qHash( oHash.rawValue() ) );

		HashIterator it = oBounds.first;

		// 2. Iterate threw all rules that include the current hash
		// (this is important for weaker hashes to deal correctly with hash collisions)
		while ( it != oBounds.second )
		{
			if ( (*it).second->match( hashes ) )
				return getUUID( (*it).second->m_idUUID );
			++it;
		}
	}

	return m_vRules.size();
}

/**
 * @brief Manager::expireLater invokes delayed rule expiry on return to the main loop.
 * Locking: REQUIRES R
 */
void Manager::expireLater()
{
	if ( !m_bExpiryRequested )
	{
		m_bExpiryRequested = true;

		signalQueue.setInterval( m_idRuleExpiry, m_tRuleExpiryInterval );
		QMetaObject::invokeMethod( this, "expire", Qt::QueuedConnection );
	}
}

/**
 * @brief Manager::remove removes the rule at nPos in the vector from the manager.
 * Note: Only rule vector locations after and equal to nPos are invalidited by calling this.
 * Locking: REQUIRES R
 * @param nPos : the position
 */
void Manager::remove(RuleVectorPos nVectorPos)
{
	Q_ASSERT( nVectorPos >= 0 && nVectorPos < m_vRules.size() );

	if ( nVectorPos == m_vRules.size() )
		return;

	Rule* pRule  = m_vRules[nVectorPos];

	// Removing the rule from special containers for fast access.
	switch ( pRule->type() )
	{
	case RuleType::IPAddress:
	{
		uint nIP = qHash( ((IPRule*)pRule)->IP() );
		IPMap::iterator it = m_lmIPs.find( nIP );

		if ( it != m_lmIPs.end() && (*it).second->m_idUUID == pRule->m_idUUID )
		{
			m_lmIPs.erase( it );
		}
	}
	break;

	case RuleType::IPAddressRange:
	{
		const IPRangeVectorPos nPos = findRange( ((IPRangeRule*)pRule)->startIP() );

		Q_ASSERT( nPos < m_vIPRanges.size() );

		if ( nPos != m_vIPRanges.size() )
		{
			Q_ASSERT( m_vIPRanges[nPos]->m_idUUID == pRule->m_idUUID );
			eraseRange( nPos );
		}
	}
	break;

#if SECURITY_ENABLE_GEOIP
	case RuleType::Country:
	{
		CountryRuleMap::iterator it = m_lmCountries.find( pRule->getContentString() );

		if ( it != m_lmCountries.end() && (*it).second->m_idUUID == pRule->m_idUUID )
		{
			m_lmCountries.erase( it );
		}

		// not all stl implementation guarantee this to have constant time...
		m_bEnableCountries = m_lmCountries.size();
	}
	break;
#endif // SECURITY_ENABLE_GEOIP

	case RuleType::Hash:
	{
		HashRule* pHashRule = (HashRule*)pRule;
		HashVector vHashes  = pHashRule->getHashes();

		HashRuleMap::iterator it;
		std::pair<HashRuleMap::iterator,HashRuleMap::iterator> oBounds;
		foreach ( CHash oHash, vHashes )
		{
			oBounds = m_lmmHashes.equal_range( qHash( oHash.rawValue() ) );
			it = oBounds.first;

			while ( it != oBounds.second )
			{
				if ( (*it).second->m_idUUID == pHashRule->m_idUUID )
				{
					m_lmmHashes.erase( it );
					break;
				}
				++it;
			}
		}
	}
	break;

	case RuleType::RegularExpression:
	{
		const RegExpVectorPos nSize = m_vRegularExpressions.size();

		if ( nSize )
		{
			RegExpVectorPos         nPos   = 0;
			const RegExpVectorPos   nMax   = nSize - 1;
			RegularExpressionRule** pArray = &m_vRegularExpressions[0]; // access internal array

			while ( nPos < nSize )
			{
				if ( pArray[nPos]->m_idUUID == pRule->m_idUUID )
					break;
			}

			while ( nPos < nMax )            // move all other elements 1 pos up the latter
			{
				pArray[nPos] = pArray[++nPos];
			}

			m_vRules.pop_back();          // remove last element
		}
	}
	break;

	case RuleType::Content:
	{
		const ContentVectorPos nSize = m_vContents.size();

		if ( nSize )
		{
			ContentVectorPos       nPos   = 0;
			const ContentVectorPos nMax   = nSize - 1;
			ContentRule**          pArray = &m_vContents[0]; // access internal array

			while ( nPos < nSize )
			{
				if ( pArray[nPos]->m_idUUID == pRule->m_idUUID )
					break;
			}

			while ( nPos < nMax )            // move all other elements 1 pos up the latter
			{
				pArray[nPos] = pArray[++nPos];
			}

			m_vRules.pop_back();          // remove last element
		}
	}
	break;

	case RuleType::UserAgent:
	{
		const UserAgentVectorPos nSize = m_vUserAgents.size();

		if ( nSize )
		{
			UserAgentVectorPos       nPos   = 0;
			const UserAgentVectorPos nMax   = nSize - 1;
			UserAgentRule**          pArray = &m_vUserAgents[0]; // access internal array

			while ( nPos < nSize )
			{
				if ( pArray[nPos]->m_idUUID == pRule->m_idUUID )
					break;
			}

			while ( nPos < nMax )            // move all other elements 1 pos up the latter
			{
				pArray[nPos] = pArray[++nPos];
			}

			m_vRules.pop_back();          // remove last element
		}
	}
	break;

	default:
#if SECURITY_ENABLE_GEOIP
		Q_ASSERT( false );
#else
		Q_ASSERT( pRule->type() == RuleType::Country );
#endif // SECURITY_ENABLE_GEOIP
	}

	m_bUnsaved = true;

	// Remove rule entry from list of all rules
	erase( nVectorPos );

	emit ruleRemoved( SharedRulePtr( pRule ) );
}

/**
 * @brief Manager::isAgentDenied checks a user agent name against the list of user agent rules.
 * Locking: REQUIRES R
 * @param sUserAgent : the user agent name
 * @return true if the user agent is denied; false otherwise
 */
bool Manager::isAgentDenied(const QString& sUserAgent)
{
	if ( sUserAgent.isEmpty() )
		return false;

	const UserAgentVectorPos nSize = m_vUserAgents.size();

	if ( nSize )
	{
		UserAgentVectorPos n   = 0;
		UserAgentRule** pArray = &m_vUserAgents[0];
		const quint32 tNow     = common::getTNowUTC();

		while ( n < nSize )
		{
			if ( !pArray[n]->isExpired( tNow ) )
			{
				if ( pArray[n]->match( sUserAgent ) /*|| pArray[n]->partialMatch( sUserAgent )*/ )
				{
					hit( pArray[n] );

					if ( pArray[n]->m_nAction == RuleAction::Deny )
					{
						return true;
					}
					else if ( pArray[n]->m_nAction == RuleAction::Accept )
					{
						return false;
					}
				}
			}
			else
			{
				expireLater();
			}

			++n;
		}
	}

	return false;
}

/**
 * @brief Manager::isDenied checks a content string against the list of list of content rules.
 * Locking: REQUIRES R
 * @param sContent : the content string
 * @return true if the content is denied; false otherwise
 */
// handled by isDenied(pHit)
/*bool Manager::isDenied(const QString& sContent)
{
	if ( sContent.isEmpty() )
		return false;

	const ContentVectorPos nSize = m_vContents.size();
	if ( nSize )
	{
	ContentVectorPos n = 0;
	ContentRule** pArray = &m_vContents[0];
	const quint32 tNow = common::getTNowUTC();

	while ( n < nSize )
	{
		if ( !pArray[n]->isExpired( tNow ) )
		{
			if ( pArray[n]->match( sContent ) )
			{
				hit( pArray[n] );

				if ( pArray[n]->m_nAction == RuleAction::Deny )
				{
					return true;
				}
				else if ( pArray[n]->m_nAction == RuleAction::Accept )
				{
					return false;
				}
			}
		}
		else
		{
			expireLater();
		}

		++n;
	}
	}

	return false;
}*/

/**
 * @brief Manager::isDenied checks a hit against hash and content rules.
 * Locking: REQUIRES R
 * @param pHit : the query hit
 * @return true if the hit is denied; false otherwise
 */
bool Manager::isDenied(const CQueryHit* const pHit)
{
	if ( !pHit )
		return false;

	const HashVector& lHashes = pHit->m_lHashes;

	const quint32 tNow = common::getTNowUTC();

	// Search for a rule matching these hashes
	RuleVectorPos nPos = getHash( lHashes );

	// If this rule matches the file, return the specified action.
	if ( nPos != m_vRules.size() )
	{
		HashRule* pHashRule = (HashRule*)m_vRules[nPos];
		if ( !pHashRule->isExpired( tNow ) )
		{
			if ( pHashRule->match( lHashes ) )
			{
				hit( pHashRule );

				if ( pHashRule->m_nAction == RuleAction::Deny )
				{
					return true;
				}
				else if ( pHashRule->m_nAction == RuleAction::Accept )
				{
					return false;
				}
			}
		}
		else
		{
			expireLater();
		}
	}


	const ContentVectorPos nSize = m_vContents.size();

	if ( nSize )
	{
		ContentVectorPos n   = 0;
		ContentRule** pArray = &m_vContents[0];

		while ( n < nSize )
		{
			if ( !pArray[n]->isExpired( tNow ) )
			{
				if ( pArray[n]->match( pHit ) )
				{
					hit( pArray[n] );

					if ( pArray[n]->m_nAction == RuleAction::Deny )
					{
						return true;
					}
					else if ( pArray[n]->m_nAction == RuleAction::Accept )
					{
						return false;
					}
				}
			}
			else
			{
				expireLater();
			}

			++n;
		}
	}

	return false;
}

/**
 * @brief Manager::isDenied checks a hit against hash and content rules.
 * Locking: REQUIRES R
 * @param lQuery : a list of all search keywords in the same order they have been entered in the
 * edit box of the GUI.
 * @param sContent : the content string/file name to be checked
 * @return true if the hit is denied; false otherwise
 */
bool Manager::isDenied(const QList<QString>& lQuery, const QString& sContent)
{
	Q_ASSERT( !lQuery.isEmpty() );

	if ( lQuery.isEmpty() || sContent.isEmpty() )
		return false;

	const RegExpVectorPos nSize = m_vRegularExpressions.size();

	if ( nSize )
	{
		RegExpVectorPos         n      = 0;
		const quint32           tNow   = common::getTNowUTC();
		RegularExpressionRule** pArray = &m_vRegularExpressions[0];

		while ( n < nSize )
		{
			if ( !pArray[n]->isExpired( tNow ) )
			{
				if ( pArray[n]->match( lQuery, sContent ) )
				{
					hit( pArray[n] );

					if ( pArray[n]->m_nAction == RuleAction::Deny )
					{
						return true;
					}
					else if ( pArray[n]->m_nAction == RuleAction::Accept )
					{
						return false;
					}
				}
			}
			else
			{
				expireLater();
			}

			++n;
		}
	}

	return false;
}

/**
 * @brief CSecurity::isPrivate checks whether a given IP is within one of the IP ranges
 * designated for private use.
 * Locking: /
 * @param oAddress: the IP
 * @return true if the IP is within a private range; false otherwise
 */
bool Manager::isPrivate(const CEndPoint& oAddress)
{
	// TODO: measure time and test
#ifdef _DEBUG
	bool bOld = isPrivateOld( oAddress );
#endif
	bool bNew = isPrivateNew( oAddress );

#ifdef _DEBUG
	Q_ASSERT( bOld == bNew );
#endif

	return bNew;
}

/**
 * @brief Manager::isPrivateOld checks an IP the old way for whether it's private.
 * @param oAddress : the IP
 * @return true if the IP is within a private range; false otherwise
 */
bool Manager::isPrivateOld(const CEndPoint& oAddress)
{
	if ( oAddress.protocol() == QAbstractSocket::IPv6Protocol )
		return false;

	if( oAddress <= CEndPoint("0.255.255.255") )
		return true;

	if( oAddress >= CEndPoint("10.0.0.0") &&
		oAddress <= CEndPoint("10.255.255.255") )
		return true;

	if( oAddress >= CEndPoint("100.64.0.0") &&
		oAddress <= CEndPoint("100.127.255.255") )
		return true;

	if( oAddress >= CEndPoint("127.0.0.0") &&
		oAddress <= CEndPoint("127.255.255.255") )
		return true;

	if( oAddress >= CEndPoint("169.254.0.0") &&
		oAddress <= CEndPoint("169.254.255.255") )
		return true;

	if( oAddress >= CEndPoint("172.16.0.0") &&
		oAddress <= CEndPoint("172.31.255.255") )
		return true;

	if( oAddress >= CEndPoint("192.0.0.0") &&
		oAddress <= CEndPoint("192.0.2.255") )
		return true;

	if( oAddress >= CEndPoint("192.168.0.0") &&
		oAddress <= CEndPoint("192.168.255.255") )
		return true;

	if( oAddress >= CEndPoint("198.18.0.0") &&
		oAddress <= CEndPoint("198.19.255.255") )
		return true;

	if( oAddress >= CEndPoint("198.51.100.0") &&
		oAddress <= CEndPoint("198.51.100.255") )
		return true;

	if( oAddress >= CEndPoint("203.0.113.0") &&
		oAddress <= CEndPoint("203.0.113.255") )
		return true;

	if( oAddress >= CEndPoint("240.0.0.0") &&
		oAddress <= CEndPoint("255.255.255.255") )
		return true;

	return false;
}

/**
 * @brief Manager::isPrivateNew checks an IP the new way for whether it's private.
 * @param oAddress : the IP
 * @return true if the IP is within a private range; false otherwise
 */
// TODO: test
bool Manager::isPrivateNew(const CEndPoint& oAddress)
{
	if ( oAddress.protocol() == QAbstractSocket::IPv6Protocol )
		return false;

	const IPRangeVectorPos nSize = m_vPrivateRanges.size();

	if ( nSize )
	{
		IPRangeRule** pRules = &m_vPrivateRanges[0];

		IPRangeVectorPos nHalf;
		IPRangeVectorPos nMiddle;
		IPRangeVectorPos nBegin = 0;
		IPRangeVectorPos n = nSize - nBegin;

		while ( n > 0 )
		{
			nHalf = n >> 1;

			nMiddle = nBegin + nHalf;

			if ( oAddress < pRules[nMiddle]->startIP() )
			{
				n = nHalf;
			}
			else
			{
				if ( oAddress <= pRules[nMiddle]->endIP() )
				{
					Q_ASSERT( pRules[nMiddle]->match( oAddress ) );
					return true;
				}
				nBegin = nMiddle + 1;
				n -= nHalf + 1;
			}
		}
	}

	return false;
}

/**
 * @brief Manager::findRange allows to find the range rule containing or next to the given IP.
 * @param oIp : the IP
 * @return m_vIPRanges.size() or the respective rule position
 */
Manager::IPRangeVectorPos Manager::findRange(const CEndPoint oAddress)
{
	const IPRangeVectorPos nSize = m_vIPRanges.size();
	if ( m_vIPRanges.empty() || !oAddress.isValid() )
	{
		return nSize;
	}

	IPRangeRule** pRules = &m_vIPRanges[0];

	IPRangeVectorPos nRemaining = nSize;
	IPRangeVectorPos nRangeStart = 0;
	IPRangeVectorPos nMiddle, nHalf, nTail;

	while ( nRemaining > 1 )
	{
		nHalf   = nRemaining >> 1;
		nTail   = nRemaining % 2;
		nMiddle = nRangeStart + nHalf;

		Q_ASSERT( 2 * nHalf + nTail );

		if ( oAddress < pRules[nMiddle]->startIP() )
		{
			--nMiddle;
			nRemaining = nHalf;
		}
		else
		{
			if ( oAddress <= pRules[nMiddle]->endIP() )
			{
				return nMiddle;
			}
			++nMiddle;

			nRemaining  = nHalf - nTail;
			nRangeStart = nMiddle;
		}
	}

	Q_ASSERT( nMiddle < nSize );
	if ( nMiddle < nSize )
	{
		Q_ASSERT( pRules[nMiddle]->startIP() <= oAddress );
		if ( nMiddle + 1 < nSize )
		{
			Q_ASSERT( pRules[nMiddle + 1]->startIP() > oAddress );
		}
	}

	return nMiddle;

	/*uint nMiddle;
	uint nBegin = 0;
	const uint nEnd = m_vIPRanges.size();

	uint n = nEnd - nBegin;

	uint nHalf;

	IPRangeRule** pRules = &m_vIPRanges[0];

	while ( n > 0 )
	{
		nHalf = n >> 1;
		//bool searchedAll = nHalf <= 1;
		nMiddle = nBegin + nHalf;

		if ( oIp < pRules[nMiddle]->startIP() )
		{
			//if ( searchedAll )
			//{
			//	return pRules[nMiddle - 1];
			//}

			n = nHalf;
		}
		else
		{
			if ( oIp <= pRules[nMiddle]->endIP() )
			{
				return pRules[nMiddle];
			}
			//else if ( searchedAll )
			//{
			//	return pRules[nMiddle];
			//}
			nBegin = nMiddle + 1; //Warum +1?
			n -= nHalf + 1;
		}
	}

	return NULL;*/
}

/*Manager::RuleVector::iterator Manager::getRWIterator(TConstIterator constIt)
{
	RuleVector::iterator i = m_vRules.begin();
	TConstIterator const_begin = m_vRules.begin();
	int nDistance = std::distance< TConstIterator >( const_begin, constIt );
	std::advance( i, nDistance );
	return i;
}*/
