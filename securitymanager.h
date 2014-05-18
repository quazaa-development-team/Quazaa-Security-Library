/*
** securitymanager.h
**
** Copyright © Quazaa Development Team, 2009-2014.
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

#ifndef SECURITYMANAGER_H
#define SECURITYMANAGER_H

#include <map>
#include <unordered_map>
#include <unordered_set>

#include <QFile>

#include "externals.h"

#include "securerule.h"

#include "contentrule.h"
#include "countryrule.h"
#include "hashrule.h"
#include "iprangerule.h"
#include "iprule.h"
#include "regexprule.h"
#include "useragentrule.h"

#include "misscache.h"
#include "sanitychecker.h"

// Increment this if there have been made changes to the way of storing security rules.
#define SECURITY_CODE_VERSION 1
// History:
// 0 - Initial implementation
// 1 - Some changes to the way the rule time is stored and other minor adjustments.

#define SECURITY_XML_VERSION "2.0"
// History:
// 1.0 - Original implementation by Shareaza
// 2.0 - Adjustments for IP ranges, Regular Expressions etc.

// TODO: add defines for hit matching
// TODO: improve doxygen
// TODO: Enable/disable GUI updating according to the visibility within the GUI
// TODO: Add last hit time to rules and make that data visible within the GUI

namespace Security
{
typedef QSharedPointer<Rule> SharedRulePtr;

typedef std::unordered_set<ID> IDSet;

/**
 * @brief The Manager class manages the security rules and allows checking content against them.
 */
class Manager : public QObject
{
	Q_OBJECT

	friend class MissCache;

	/* ========================================================================================== */
	/* ====================================== Definitions  ====================================== */
	/* ========================================================================================== */
private:
	typedef std::vector< Rule*  > RuleVector;

	// use this if you don't want to care about signed/unsigned...
	typedef RuleVector::size_type RuleVectorPos;

	typedef std::hash< QHostAddress > IPHasher;
	typedef std::unordered_map< quint32, IPRule*      > IPMap;
#if SECURITY_ENABLE_GEOIP
	typedef std::unordered_map< quint32, CountryRule* > CountryMap;
#endif // SECURITY_ENABLE_GEOIP

	typedef std::vector< IPRangeRule*           >   IPRangeVector;
	typedef std::vector< RegularExpressionRule* >    RegExpVector;
	typedef std::vector< UserAgentRule*         > UserAgentVector;
	typedef std::vector< ContentRule*           >   ContentVector;

	// integer types for container positions
	typedef   IPRangeVector::size_type   IPRangeVectorPos;
	typedef    RegExpVector::size_type    RegExpVectorPos;
	typedef UserAgentVector::size_type UserAgentVectorPos;
	typedef   ContentVector::size_type   ContentVectorPos;

	typedef std::pair< uint, HashRule*          > HashPair;
	// Note: Using a multimap eliminates eventual problems of hash
	// collisions caused by weaker hashes like MD5 for example.
	typedef std::multimap< uint, HashRule*      > HashRuleMap;
	typedef HashRuleMap::const_iterator HashIterator;

	/* ========================================================================================== */
	/* ======================================= Attributes ======================================= */
	/* ========================================================================================== */
public:
	mutable QReadWriteLock  m_oRWLock;
	SanityCecker            m_oSanity; // has its own locking

#ifndef QUAZAA_SETUP_UNIT_TESTS
private:
#else
public:
#endif
	// contains all rules
	RuleVector      m_vRules;

	// single IP blocking rules
	IPHasher        m_oIPHasher;
	IPMap           m_lmIPs;

	// multiple IP blocking rules
	IPRangeVector   m_vIPRanges;
	IPRangeVector   m_vPrivateRanges;

	// country rules
#if SECURITY_ENABLE_GEOIP
	bool            m_bEnableCountries;
	CountryHasher   m_oCountryHasher;
	CountryMap      m_lmCountries;
#endif // SECURITY_ENABLE_GEOIP

	// hash rules
	HashRuleMap     m_lmmHashes;

	// all other content rules
	ContentVector   m_vContents;

	// RegExp rules
	RegExpVector    m_vRegularExpressions;

	// User agent rules
	UserAgentVector m_vUserAgents;

	// Miss cache
	MissCache       m_oMissCache;

	// Security manager settings
	bool            m_bLogIPCheckHits;          // Post log message on IsDenied( QHostAdress ) call
	quint64         m_tRuleExpiryInterval;      // Check the security manager for expired hosts each x milliseconds

	// Timer IDs
	QUuid           m_idRuleExpiry;       // The ID of the signalQueue object.

	// Other
	mutable bool    m_bUnsaved;           // true if there are unsaved rules
	bool            m_bShutDown;
	bool            m_bExpiryRequested;
	bool            m_bDenyPrivateIPs;

	bool            m_bDenyPolicy;
	// m_bDenyPolicy == false : everything but specifically blocked IPs is allowed (default)
	// m_bDenyPolicy == true  : everything but specifically allowed IPs is rejected
	// Note that the default policy is only applied to IP related rules, as using it for everything
	// else does not make any sense.

	QMetaMethod     m_pfExpire;

public:
	/* ========================================================================================== */
	/* ====================================== Construction ====================================== */
	/* ========================================================================================== */
	Manager();
	~Manager();

	/* ========================================================================================== */
	/* ======================================= Operations ======================================= */
	/* ========================================================================================== */
	/**
	 * @brief Manager::getCount allows access to the amount of rules managed by the manager.
	 * Locking: REQUIRES R
	 * @return the amount of rules.
	 */
	RuleVectorPos   count() const;

	/**
	 * @brief Manager::denyPolicy allows access to the current deny policy.
	 * Locking: REQUIRES R
	 * @return the current deny policy.
	 */
	bool            denyPolicy() const;

	/**
	 * @brief Manager::setDenyPolicy sets the deny policy to a given value.
	 * Locking: RW
	 * @param bDenyPolicy
	 */
	void            setDenyPolicy( bool bDenyPolicy );

	/**
	 * @brief Manager::check allows to see whether a rule with the same UUID exists within the
	 * manager.
	 * Locking: R
	 * @param pRule the rule to be verified.
	 * @return true if the rule exists within the manager; false otherwise.
	 */
	bool            check( const Rule* const pRule ) const;

	/**
	 * @brief Manager::add adds a rule to the security database.
	 * Note: This makes no copy of the rule, so don't delete it after adding.
	 * Locking: RW
	 * @param pRule: the rule to be added. Will be set to NULL if redundant.
	 * @return true if the rule has been added; false otherwise
	 */
	bool            add( Rule* pRule, bool bDoSanityCheck = true );

	/**
	 * @brief Manager::remove removes a rule from the manager.
	 * Reminder: Do not delete the rule after calling this, it will be deleted automatically once
	 * the GUI has been updated.
	 * Locking: RW
	 * @param pRule : the rule
	 */
	void            remove( const Rule* const pRule );

	/**
	 * @brief Manager::clear frees all memory and storage containers. Removes all rules.
	 * Locking: RW
	 */
	void            clear();

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
	void            ban( const QHostAddress& oAddress, RuleTime::Time nBanLength,
						 bool bMessage = true, const QString& sComment = "", bool bAutomatic = true
#if SECURITY_LOG_BAN_SOURCES
																							   , const QString& sSender = ""
#endif
					   );

	/**
	 * @brief Manager::ban bans a given file for a specified amount of time.
	 * Locking: R + RW (call to add())
	 * @param pHit : the file hit
	 * @param nBanLength : the amount of time until the ban shall expire
	 * @param nMaxHashes : the maximum amount of hashes to add to the rule
	 * @param sComment : comment; if blanc, a default comment is generated depending on nBanLength
	 */
	void            ban( const QueryHit* const pHit, RuleTime::Time nBanLength,
						 quint8 nMaxHashes = 3, const QString& sComment = "" );

	/**
	 * @brief Manager::isDenied checks an IP against the security database.
	 * Locking: R
	 * @param oAddress : the IP
	 * @return true if the IP is denied; false otherwise
	 */
	bool            isDenied( const EndPoint& oAddress );

	/**
	 * @brief Manager::isDenied checks a hit against the security database.
	 * Note: This does not verify the hit IP to avoid redundant checking.
	 * Locking: R
	 * @param pHit : the hit
	 * @param lQuery : a list of all search keywords in the same order they have been entered in the
	 * edit box of the GUI.
	 * @return true if the IP is denied; false otherwise
	 */
	bool            isDenied( const QueryHit* const pHit, const QList<QString>& lQuery );

	/**
	 * @brief Manager::isClientBad checks for bad user agents.
	 * Note: We don't actually ban these clients, but we don't accept them as a leaf. They are
	 * allowed to upload, though.
	 * Locking: /
	 * @param sUserAgent
	 * @return true if the remote computer is running a client that is breaking GPL, causing
	 * problems etc.; false otherwise
	 */
	bool            isClientBad( const QString& sUserAgent ) const;

	/**
	 * @brief Manager::isAgentBlocked checks the agent string for banned clients.
	 * Locking: R
	 * @param sUserAgent : the agent string to be checked
	 * @return true for especially bad / leecher clients, as well as user defined agent blocks.
	 */
	bool            isAgentDenied( const QString& sUserAgent );

	/**
	 * @brief Manager::isVendorBlocked checks for blocked vendors.
	 * Locking: /
	 * @param sVendor
	 * @return true for blocked vendors; false otherwise
	 */
	bool            isVendorBlocked( const QString& sVendor ) const;

	/**
	 * @brief Manager::registerMetaTypes registers the necessary meta types for signals and slots.
	 */
	void            registerMetaTypes();

	/**
	 * @brief Manager::start starts the Security Manager.
	 * Initializes signal/slot connections, pulls settings and sets up cleanup interval counters.
	 * Locking: RW
	 * @return true if loading the rules was successful; false otherwise
	 */
	bool            start(); // connects signals etc.

	/**
	 * @brief Manager::stop prepares the security manager for destruction.
	 * Saves the rules to disk, disonnects signal/slot connections, frees memory
	 * and clears up storage containers.
	 * Locking: RW
	 * @return true if saving was successful; false otherwise
	 */
	void            stop(); // makes the Security Manager ready for destruction

	/**
	 * @brief Manager::load loads the rule database from the HDD.
	 * Locking: RW
	 * @return true if successful; false otherwise
	 */
	bool            load();

	/**
	 * @brief Manager::save writes the security rules to HDD.
	 * Skips saving if there haven't been any important changes and bForceSaving is not set to true.
	 * Locking: R
	 * @param bForceSaving : use this to prevent the manager from taking the decision that saving
	 * isn't needed ATM
	 * @return true if saving has been successfull/saving has been skipped; false otherwise
	 */
	void            save( bool bForceSaving = false ) const;

	/**
	 * @brief Manager::writeToFile is a helper method required for save().
	 * Locking: Requires R
	 * @param pManager : the security manager
	 * @param oFile : the file to be written to
	 * @return the number of rules written to file
	 */
	static quint32  writeToFile( const void* const pManager, QFile& oFile ); // used by save()

	/**
	 * @brief Manager::import imports a security file with unknown format located at sPath.
	 * Locking: RW
	 * @param sPath : the location
	 * @return true on success; false otherwise
	 */
	bool            import( const QString& sPath );

	/**
	 * @brief Manager::fromP2P imports a P2P rule file into the manager.
	 * Locking: RW
	 * @param sPath : the file location
	 * @return true if successful; false otherwise
	 */
	bool            fromP2P( const QString& sPath );

	/**
	 * @brief Manager::xmlns contains the xml file schema specification.
	 */
	static const QString xmlns;

	/**
	 * @brief Manager::fromXML imports rules from an XML file.
	 * Locking: RW
	 * @param sPath : the path to the XML file.
	 * @return true if at least one rule could be imported; false otherwise
	 */
	bool            fromXML( const QString& sPath );

	/**
	 * @brief toXML Exports all rules to a Security XML file.
	 * Locking: R
	 * @param sPath The path to the new file.
	 * @param lsIDs The GUI IDs of the rules to write to the XML file. If this is not provided, all
	 * rules are written to file.
	 * @return true if successful; false otherwise.
	 */
	bool            toXML( const QString& sPath, const IDSet& lsIDs = IDSet() ) const;

	/**
	 * @brief Manager::emitUpdate emits a ruleUpdated signal for a given GUI ID nID.
	 * Locking: /
	 * @param nID : the ID
	 */
	void            emitUpdate( ID nID );

	/* ========================================================================================== */
	/* ======================================== Signals  ======================================== */
	/* ========================================================================================== */
signals:
	/**
	 * @brief startUpFinished informs about the Security Manager startup having been finished.
	 */
	void            startUpFinished();

	/**
	 * @brief ruleAdded informs about a new rule having been added.
	 * @param pRule : the rule
	 */
	void            ruleAdded( Rule* pRule );

	/**
	 * @brief ruleRemoved informs about a rule having been removed.
	 * @param pRule : the rule
	 */
	void            ruleRemoved( SharedRulePtr pRule );

	/**
	 * @brief ruleInfo info signal to get informed about all rules within the manager.
	 * See Manager::requestRuleList() for more information.
	 * @param pRule : the rule
	 */
	void            ruleInfo( Rule* pRule );

	/**
	 * @brief ruleUpdated informs about a rule having been updated.
	 * @param nID : the GUI ID of the updated rule
	 */
	void            ruleUpdated( ID nID );

	/**
	 * @brief cleared informs about the manager having been cleared.
	 */
	void            cleared();

	/**
	 * @brief updateLoadMax informs about a change in the max value of the loading progress bar.
	 * @param max : the new max value
	 */
	void            updateLoadMax( int max );

	/**
	 * @brief updateLoadProgress updates the load progress bar.
	 * @param progress : the new progress
	 */
	void            updateLoadProgress( int progress );

	/* ========================================================================================== */
	/* ========================================= Slots  ========================================= */
	/* ========================================================================================== */
public slots:
	/**
	 * @brief Manager::requestRuleInfo allows to request ruleInfo() signals for all rules.
	 * Qt slot. Triggers the Security Manager to emit all rules using the ruleInfo() signal.
	 * Locking: R
	 * @return the number of rule info signals to expect
	 */
	quint32         requestRuleInfo();

	/**
	 * @brief Manager::expire removes rules that have reached their expiration date.
	 * Qt slot. Checks the security database for expired rules.
	 * Locking: RW
	 */
	void            expire();

	/**
	 * @brief Manager::settingsChanged needs to be triggered on setting changes.
	 * Qt slot. Pulls all relevant settings from quazaaSettings.Security
	 * and refreshes all components depending on them.
	 * Locking: RW
	 */
	void            settingsChanged();

	/**
	 * @brief shutDown is to be triggered on application shutdown.
	 * Locking: RW
	 */
	void            shutDown();

private slots:
	/**
	 * @brief updateHitCount
	 * @param ruleID
	 * @param nCount
	 */
	void            updateHitCount( QUuid ruleID, uint nCount );

	/* ========================================================================================== */
	/* ======================================== Privates ======================================== */
	/* ========================================================================================== */
#ifndef QUAZAA_SETUP_UNIT_TESTS
private:
#else
public:
#endif
	/**
	 * @brief Manager::hit increases the rule counters and emits an updating signal to the GUI.
	 * Locking: /
	 * @param pRule : the rule that has been hit
	 */
	void            hit( Rule* pRule );

	/**
	 * @brief Manager::loadPrivates loads the private IP renges into the appropriate container.
	 * Locking RW
	 */
	void            loadPrivates();

	/**
	 * @brief Manager::clearPrivates clears the private rules from the respective container.
	 */
	void            clearPrivates();

	/**
	 * @brief Manager::load loads rules from HDD file into manager.
	 * Locking: RW
	 * @param sPath : the location of the rule file on disk
	 * @return true if loading was successful; false otherwise
	 */
	bool            load( const QString& sPath );

	/**
	 * @brief insert Inserts a new rule at the correct place into the rules vector.
	 * Locking: REQUIRES RW
	 * @param pRule : The rule to be inserted into the rules vector.
	 */
	void            insert( Rule* pRule );

	/**
	 * @brief Manager::erase removes the rule at the position nPos from the vector.
	 * Locking: REQUIRES RW
	 * @param nPos : the position
	 */
	void            erase( RuleVectorPos nPos );

	/**
	 * @brief Manager::insertRange inserts a range rule into the respective container.
	 * Locking: REQUIRES RW
	 * @param pNew : the range rule
	 */
	void            insertRange( IPRangeRule*& pNew );

	/**
	 * @brief Manager::insertRangeHelper inserts a range rule at the correct place into the vector.
	 * @param pNewRange : the range rule
	 */
	void            insertRangeHelper( IPRangeRule* pNewRange );

	/**
	 * @brief Manager::erase removes the rule at the position nPos from the IP ranges vector.
	 * Locking: REQUIRES RW
	 * @param nPos : the position
	 */
	void            eraseRange( const IPRangeVectorPos nPos );

	/**
	 * @brief findInternal Allows to determine the theoretical position of the rule with idUUID
	 * within pRules.
	 * Locking: REQUIRES R
	 * @param idUUID The rule ID
	 * @param pRules Array containing pointers to rules.
	 * @param nSize The size of that array.
	 * @return The theoretical rule position nPos with
	 * ( pRules[nPos]    ->m_idUUID <= idUUID ) &&
	 * ( nPos + 1 == nSize || pRules[nPos + 1]->m_idUUID > idUUID )
	 */
	RuleVectorPos   findInternal( const QUuid& idUUID, const Rule* const * const pRules,
								  const RuleVectorPos nSize ) const;

	/**
	 * @brief Manager::getUUID returns the rule position for the given UUID.
	 * Note that there is always max one rule per UUID.
	 * Locking: REQUIRES R
	 * @param idUUID : the rule UUID
	 * @return the rule position; m_vRules.size() if no rule by the specified ID could be found.
	 */
	RuleVectorPos   find( const QUuid& idUUID ) const;

	/**
	 * @brief Manager::getHash
	 * Note: this returns the first rule found. There might be others, however.
	 * Locking: REQUIRES R
	 * @param hashes : a vector of hashes to look for
	 * @return the rule position
	 */
	RuleVectorPos   find( const HashSet& vHashes ) const;

	/**
	 * @brief Manager::expireLater invokes delayed rule expiry on return to the main loop.
	 * Locking: REQUIRES R
	 */
	void            expireLater();

	/**
	 * @brief Manager::remove removes the rule at nPos in the vector from the manager.
	 * Note: Only rule vector locations after and equal to nPos are invalidited by calling this.
	 * Note: Caller needs to make sure the rule is not accessed anymore aftor calling this, as it is
	 * given over to a QSharedPointer which will expire as soon as the GUI has removed the rule.
	 * Locking: REQUIRES RW
	 * @param nPos : the position
	 */
	void            remove( const RuleVectorPos nVectorPos );

	/**
	 * @brief Manager::isAgentDenied checks a user agent name against the list of user agent rules.
	 * Locking: REQUIRES R
	 * @param sUserAgent : the user agent name
	 * @return true if the user agent is denied; false otherwise
	 */
	bool            isAgentDeniedInternal( const QString& sUserAgent );

	/**
	 * @brief Manager::isDenied checks a content string against the list of list of content rules.
	 * Locking: REQUIRES R
	 * @param sContent : the content string
	 * @return true if the content is denied; false otherwise
	 */
//	bool            isDenied(const QString& sContent);

	/**
	 * @brief Manager::isDenied checks a hit against hash and content rules.
	 * Locking: REQUIRES R
	 * @param pHit : the query hit
	 * @return true if the hit is denied; false otherwise
	 */
	bool            isDenied( const QueryHit* const pHit );

	/**
	 * @brief Manager::isDenied checks a hit against hash and content rules.
	 * Locking: REQUIRES R
	 * @param lQuery : a list of all search keywords in the same order they have been entered in the
	 * edit box of the GUI.
	 * @param sContent : the content string/file name to be checked
	 * @return true if the hit is denied; false otherwise
	 */
	bool            isDenied( const QList<QString>& lQuery, const QString& sContent );

	/**
	 * @brief CSecurity::isPrivate checks whether a given IP is within one of the IP ranges
	 * designated for private use.
	 * Locking: /
	 * @param oAddress: the IP
	 * @return true if the IP is within a private range; false otherwise
	 */
	bool            isPrivate( const EndPoint& oAddress );

#if SECURITY_DISABLE_IS_PRIVATE_OLD
	/**
	 * @brief Manager::isPrivateOld checks an IP the old way for whether it's private.
	 * @param oAddress : the IP
	 * @return true if the IP is within a private range; false otherwise
	 */
	bool            isPrivateOld( const EndPoint& oAddress );

	/**
	 * @brief Manager::isPrivateNew checks an IP the new way for whether it's private.
	 * @param oAddress : the IP
	 * @return true if the IP is within a private range; false otherwise
	 */
	bool            isPrivateNew( const EndPoint& oAddress );
#endif // SECURITY_DISABLE_IS_PRIVATE_OLD

	/**
	 * @brief findRangeForMerge allows to find the range rule containing or next to a given IP.
	 * @param oIp : the IP
	 * @return first range with a oAddress >= startIP(), (e.g. the only range that might be
	 * containing the given IP); m_vIPRanges.size() if no such range exists.
	 */
	IPRangeVectorPos findRangeForMerging( const EndPoint& oAddress );

	/**
	 * @brief findRangeMatch allows to find the range rule containing a given IP.
	 * @param oIp : the IP
	 * @param nPos : a value by reference that will be set to the rule pos within the vector
	 * @return the range rule matching oAddress; NULL if no such range rule exists.
	 */
	IPRangeRule* findRangeMatch( const EndPoint& oAddress, IPRangeVectorPos& nPos );

	/**
	 * @brief getRWIterator converts a const_iterator to an iterator
	 * @param constIt : the const_iterator
	 * @return an iterator
	 */
	//RuleVector::iterator getRWIterator(TConstIterator constIt);
};

}

extern Security::Manager securityManager;

#endif // SECURITYMANAGER_H
