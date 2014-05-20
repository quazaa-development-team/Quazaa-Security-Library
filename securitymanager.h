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
#define SECURITY_CODE_VERSION 2
// History:
// 0 - Initial implementation
// 1 - Some changes to the way the rule time is stored and other minor adjustments.
// 2 - Added last hit time to rules

#define SECURITY_XML_VERSION "2.0"
// History:
// 1.0 - Original implementation by Shareaza
// 2.0 - Adjustments for IP ranges, Regular Expressions etc.

// TODO: check agent/vendor bad/denied calls

namespace Security
{
/**
 * @brief SharedRulePtr represents a security Rule.
 */
typedef QSharedPointer<Rule> SharedRulePtr;

/**
 * @brief IDSet represents a set of Rule GUI IDs.
 */
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
	SanityChecker            m_oSanity;

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
	quint64         m_tRuleExpiryInterval;      // Check the security manager for expired hosts
												// each x milliseconds

	// Timer IDs
	QUuid           m_idRuleExpiry;       // The ID of the signalQueue object.

	// Other
	mutable bool    m_bUnsaved;           // true if there are unsaved rules
	bool            m_bShutDown;
	bool            m_bExpiryRequested;
	bool            m_bDenyPrivateIPs;

	/**
	 * @brief m_bDenyPolicy specifies the default deny policy for IP checking.
	 * <br><b>Values:</b>
	 * <br><code>true </code> - all but specifically allowed IPs are rejected
	 * <br><code>false</code> - all but specifically blocked IPs are allowed (default)
	 */
	bool            m_bDenyPolicy;

	QMetaMethod     m_pfExpire;

	/**
	 * @brief sXMLNameSpace contains the namespace specification for Sheareza securiy XML files,
	 * as used by Quazaa to export security rules to XML.
	 */
	static const QString sXMLNameSpace;

public:
	/* ========================================================================================== */
	/* ====================================== Construction ====================================== */
	/* ========================================================================================== */
	/**
	 * @brief Manager constructs an empty security manager. Note that you should call start() before
	 * actually using it.
	 * @see start()
	 */
	Manager();
	~Manager();

	/* ========================================================================================== */
	/* ======================================= Operations ======================================= */
	/* ========================================================================================== */
	/**
	 * @brief count allows access to the amount of rules within the Manager.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @return the number of rules
	 */
	RuleVectorPos   count() const;

	/**
	 * @brief denyPolicy allows access to the current deny policy.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @return the current deny policy
	 */
	bool            denyPolicy() const;

	/**
	 * @brief setDenyPolicy sets the deny policy to a given value.
	 * <br><b>Locking: RW</b>
	 *
	 * @param bDenyPolicy  The new default value returned by isDenied if no match for the requested
	 * content could be found in the Manager.
	 */
	void            setDenyPolicy( bool bDenyPolicy );

	/**
	 * @brief check allows to see whether a Rule with the same UUID exists within the Manager.
	 * <br><b>Locking: R</b>
	 *
	 * @param pRule  The rule to be verified.
	 * @return <code>true</code> if such a rule exists within the manager;
	 * <br><code>false</code> otherwise
	 */
	bool            check( const Rule* const pRule ) const;

	/**
	 * @brief add inserts a rule into the security database.
	 * <br><b>Locking: RW</b>
	 *
	 * Note: This takes ownership of the rule, so don't delete it after adding.
	 *
	 * @param pRule  The rule to be added. Will be set to NULL if redundant.
	 * @return <code>true</code> if the Rule has been added;
	 * <br><code>false</code> otherwise
	 */
	bool            add( Rule* pRule, bool bDoSanityCheck = true );

	/**
	 * @brief remove removes a Rule from the Manager.
	 * <br><b>Locking: RW</b>
	 *
	 * Reminder: Do not delete the rule after calling this, it will be deleted automatically once
	 * the GUI has been updated. Note that this will assert if the rule in question does not exist.
	 *
	 * @param pRule  The Rule to remove.
	 */
	void            remove( const Rule* const pRule );

	/**
	 * @brief clear frees all memory and storage containers. Removes all rules.
	 * <br><b>Locking: RW</b>
	 */
	void            clear();

	/**
	 * @brief ban bans a given IP for a specified amount of time.
	 * <br><b>Locking: R + RW</b> (call to add())
	 *
	 * @param oAddress    The IP to ban.
	 * @param nBanLength  The amount of time until the ban shall expire.
	 * @param bMessage    Whether a message shall be posted to the system log.
	 * @param sComment    The Rule comment; if blanc, a default comment is generated depending
	 * on nBanLength
	 * @param bAutomatic  Whether this was an automatic ban (as opposed to a manual ban by the user)
	 * @param sSender     String representation of the caller (for debugging purposes only)
	 */
	void            ban( const QHostAddress& oAddress, RuleTime::Time nBanLength,
						 bool bMessage = true, const QString& sComment = "", bool bAutomatic = true
#if SECURITY_LOG_BAN_SOURCES
						 , const QString& sSender = ""
#endif
						);

	/**
	 * @brief ban bans a given file for a specified amount of time.
	 * <br><b>Locking: R + RW</b> (during call to add())
	 *
	 * @param pHit        The search file hit.
	 * @param nBanLength  The amount of time until the ban shall expire.
	 * @param nMaxHashes  The maximum amount of hashes to add to the rule.
	 * @param sComment    Comment; if blanc, a default comment is generated depending on nBanLength.
	 */
	void            ban( const QueryHit* const pHit, RuleTime::Time nBanLength,
						 quint8 nMaxHashes = 3, const QString& sComment = "" );

	/**
	 * @brief isDenied checks an IP against the security database.
	 * <br><b>Locking: R</b>
	 *
	 * @param oAddress  The IP to check.
	 * @return <code>true</code> if the IP is denied; <br><code>false</code> otherwise.
	 */
	bool            isDenied( const EndPoint& oAddress );

	/**
	 * @brief isDenied checks a hit against the security database.
	 * <br><b>Locking: R</b>
	 *
	 * Note: This does not verify the hit IP to avoid redundant checking.
	 *
	 * @param pHit    The QueryHit to check.
	 * @param lQuery  A list of all search keywords in the same order they have been entered in the
	 * edit box of the GUI.
	 * @return <code>true</code> if the QueryHit is denied; <br><code>false</code> otherwise.
	 */
	bool            isDenied( const QueryHit* const pHit, const QList<QString>& lQuery );

	/**
	 * @brief isClientBad checks for bad user agents.
	 * <br><b>Locking: /</b>
	 *
	 * Note: We don't actually ban these clients, but we don't accept them as a leaf. They are
	 * allowed to upload, though.
	 *
	 * @param sUserAgent  The user agent to check against the list of bad user agents.
	 * @return <code>true</code> if the remote computer is running a client that is breaking GPL,
	 * causing problems etc.; <br><code>false</code> otherwise.
	 */
	bool            isClientBad( const QString& sUserAgent ) const;

	/**
	 * @brief isAgentBlocked checks the agent string for banned clients.
	 * <br><b>Locking: R</b>
	 *
	 * @param sUserAgent  The agent string to be checked.
	 * @return <code>true</code> for especially bad / leecher clients, as well as user defined agent
	 * blocks; <br><code>false</code> otherwise.
	 */
	bool            isAgentDenied( const QString& sUserAgent );

	/**
	 * @brief isVendorBlocked checks for blocked vendors.
	 * <br><b>Locking: /</b>
	 *
	 * @param sVendor  The vendor code.
	 * @return <code>true</code> for blocked vendors; <br><code>false</code> otherwise.
	 */
	bool            isVendorBlocked( const QString& sVendor ) const;

	/**
	 * @brief registerMetaTypes registers the necessary meta types for using the signals
	 * and slots of the Security Manager.
	 * <br><b>Locking: /</b>
	 */
	void            registerMetaTypes();

	/**
	 * @brief start starts the Security Manager.
	 * <br><b>Locking: RW</b>
	 *
	 * Initializes signal/slot connections, pulls settings and sets up cleanup interval counters.
	 *
	 * @return <code>true</code> if loading the Security Rules from disk was successful;
	 * <br><code>false</code> otherwise.
	 */
	bool            start();

	/**
	 * @brief stop prepares the security manager for destruction.
	 * <br><b>Locking: RW</b>
	 *
	 * Saves the rules to disk, disonnects signal/slot connections, frees memory and clears up
	 * storage containers.
	 *
	 * @return <code>true</code> if saving was successful; <br><code>false</code> otherwise
	 */
	void            stop();

	/**
	 * @brief load loads the rule database from the HDD.
	 * <br><b>Locking: RW</b>
	 *
	 * @return <code>true</code> if successful; <br><code>false</code> otherwise
	 */
	bool            load();

	/**
	 * @brief save writes the security rules to HDD.
	 * <br><b>Locking: R</b>
	 *
	 * Skips saving if there haven't been any important changes and <code>bForceSaving</code> is not
	 * set to <code>true</code>.
	 *
	 * @param bForceSaving  Use this to prevent the Manager from taking the decision that saving
	 * isn't needed ATM.
	 */
	void            save( bool bForceSaving = false ) const;

	/**
	 * @brief writeToFile is a helper method required for save().
	 * <br><b>Locking: Requires R</b>
	 *
	 * @param pManager  The Security Manager.
	 * @param oFile     The file to be written to.
	 * @return the number of rules written to file
	 */
	static quint32  writeToFile( const void* const pManager, QFile& oFile ); // used by save()

	/**
	 * @brief import imports a security file with unknown format located at sPath.
	 * <br><b>Locking: RW</b>
	 *
	 * @param sPath  The file location.
	 * @return <code>true</code> on success; <br><code>false</code> otherwise
	 */
	bool            import( const QString& sPath );

	/**
	 * @brief fromP2P imports a P2P rule file into the Manager.
	 * <br><b>Locking: RW</b>
	 *
	 * @param sPath  The file location.
	 * @return <code>true</code> if successful; <br><code>false</code> otherwise
	 */
	bool            fromP2P( const QString& sPath );

	/**
	 * @brief fromXML imports rules from a Shareaza style Security XML file.
	 * <br><b>Locking: RW</b>
	 *
	 * @param sPath  The path to the Shareaza security XML file.
	 * @return <code>true</code> if at least one rule could be imported;
	 * <br><code>false</code> otherwise
	 */
	bool            fromXML( const QString& sPath );

	/**
	 * @brief toXML exports all rules to a Shareaza style Security XML file.
	 * <br><b>Locking: R</b>
	 *
	 * @param sPath  The path to the new file.
	 * @param lsIDs  The GUI IDs of the rules to write to the XML file. If this is not provided or
	 * empty, all rules are written to file.
	 * @return <code>true</code> if successful; <br><code>false</code> otherwise
	 */
	bool            toXML( const QString& sPath, const IDSet& lsIDs = IDSet() ) const;

	/**
	 * @brief emitUpdate emits a ruleUpdated signal for a given GUI ID nID.
	 * <br><b>Locking: /</b>
	 *
	 * @param nID  The rule GUI ID.
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
	 * @brief ruleAdded informs about a new Rule having been added.
	 * @param pRule  The newly added Rule.
	 */
	void            ruleAdded( Rule* pRule );

	/**
	 * @brief ruleRemoved informs about a Rule having been removed.
	 * @param pRule  The newly removed Rule.
	 */
	void            ruleRemoved( SharedRulePtr pRule );

	/**
	 * @brief ruleInfo is an info signal to get informed about all rules within the Manager.
	 * See requestRuleList() for more information.
	 * @param pRule  A Rule within the Manager.
	 */
	void            ruleInfo( Rule* pRule );

	/**
	 * @brief ruleUpdated informs about a Rule having been updated.
	 * @param nID  The GUI ID of the updated Rule.
	 */
	void            ruleUpdated( ID nID );

	/**
	 * @brief cleared informs about the Manager having been cleared.
	 */
	void            cleared();

	/**
	 * @brief updateLoadMax informs about a change in the max value of the loading progress bar.
	 * @param nMax  The new maximum value.
	 */
	void            updateLoadMax( int nMax );

	/**
	 * @brief updateLoadProgress updates the loading progress bar.
	 * @param nProgress  The new load progress.
	 */
	void            updateLoadProgress( int nProgress );

	/* ========================================================================================== */
	/* ========================================= Slots  ========================================= */
	/* ========================================================================================== */
public slots:
	/**
	 * @brief requestRuleInfo allows to request ruleInfo signals for all rules.
	 * <br><b>Locking: R</b>
	 *
	 * Remember using queued connections when connceting to the ruleInfo signal, else you risk
	 * recieving the signals before this method returns.
	 * @see ruleInfo()
	 * @return the number of rule info signals for the caller to expect
	 */
	quint32         requestRuleInfo();

	/**
	 * @brief expire removes rules that have reached their expiration date.
	 * <br><b>Locking: RW</b>
	 */
	void            expire();

	/**
	 * @brief settingsChanged pulls all relevant settings from quazaaSettings.Security and
	 * refreshes all components depending on them.
	 * <br><b>Locking: RW</b>
	 *
	 * Note: This needs to be triggered on setting changes.
	 */
	void            settingsChanged();

	/**
	 * @brief shutDown is to be triggered on application shutdown.
	 * <br><b>Locking: RW</b>
	 */
	void            shutDown();

private slots:
	/**
	 * @brief updateHitCount adds the amount nCount of hits to the Rule with the UUID ruleID.
	 * <br><b>Locking: R</b>
	 *
	 * @param ruleID  The UUID of the Rule to be updated.
	 * @param nCount  The number of hits to add to the specified Rule.
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
	 * @brief hit increases the rule counters by 1 and emits an updating signal to the GUI.
	 * <br><b>Locking: /</b>
	 *
	 * @param pRule  The Rule that has been hit.
	 */
	void            hit( Rule* pRule );

	/**
	 * @brief loadPrivates loads the private IP ranges into the appropriate container.
	 * <br><b>Locking: RW</b>
	 */
	void            loadPrivates();

	/**
	 * @brief clearPrivates clears the private rules from the respective container.
	 * <br><b>Locking: REQUIRES RW</b>
	 */
	void            clearPrivates();

	/**
	 * @brief load retrieves the rules from HDD and adds them to the Manager.
	 * <br><b>Locking: RW</b>
	 *
	 * @param sPath  The location of the rule serialization file on disk.
	 * @return <code>true</code> if loading was successful; <code>false</code> otherwise
	 */
	bool            load( const QString& sPath );

	/**
	 * @brief insert sorts a new rule at the correct place into the rules vector.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * @param pRule  The Rule to be inserted into the vector.
	 */
	void            insert( Rule* pRule );

	/**
	 * @brief erase removes the Rule at the position nPos from the vector.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * Note: this does not free the memory of the Rule. The caller needs to make sure of that.
	 * See the QSharedPointer emitted at the end of remove( RuleVectorPos ) for that.
	 *
	 * @param nPos  Where to remove the Rule.
	 */
	void            erase( RuleVectorPos nPos );

	/**
	 * @brief insertRange inserts an IPRangeRule into the respective container.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * @param pNew  The IPRangeRule to insert.
	 */
	void            insertRange( IPRangeRule*& pNew );

	/**
	 * @brief insertRangeHelper inserts an IPRangeRule at the correct place into the vector.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * @param pNewRange  The IPRangeRule to insert.
	 */
	void            insertRangeHelper( IPRangeRule* pNewRange );

	/**
	 * @brief erase removes the Rule at the position nPos from the IP ranges vector.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * Note: The caller must make sure the memory is freed. This usually happens in the GUI.
	 *
	 * @param nPos  Where to remove the Rule.
	 */
	void            eraseRange( const IPRangeVectorPos nPos );

	/**
	 * @brief findInternal Allows to determine the theoretical position of the rule with idUUID
	 * within pRules.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param idUUID  The rule ID.
	 * @param pRules  Array containing pointers to rules sorted by UUID.
	 * @param nSize   The size of that array.
	 * @return the theoretical RuleVectorPos nPos with
	 * <br><code>( pRules[nPos]->m_idUUID == idUUID ) ||</code>
	 * <br><code>( pRules[nPos]->m_idUUID > idUUID && !nPos
	 * || pRules[nBegin - 1]->m_idUUID < idUUID )</code>
	 */
	RuleVectorPos   findInternal( const QUuid& idUUID, const Rule* const * const pRules,
								  const RuleVectorPos nSize ) const;

	/**
	 * @brief find returns the Rule position for the given UUID.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * Note that there is always at maximum one Rule per UUID.
	 *
	 * @param idUUID  The rule UUID.
	 * @return the RuleVectorPos of the Rule;
	 * <br><code>m_vRules.size()</code> if no Rule by the specified ID could be found.
	 */
	RuleVectorPos   find( const QUuid& idUUID ) const;

	/**
	 * @brief find allows to determine the RuleVectorPos of the Rule matching vHashes.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * Note: This returns the first rule found. There might be others, however.
	 *
	 * @param vHashes  The HashSet of hashes to look for.
	 * @return the RuleVectorPos of the HashRule;
	 * <br><code>m_vRules.size()</code> if no HashRule by the specified HashSet could be found.
	 */
	RuleVectorPos   find( const HashSet& vHashes ) const;

	/**
	 * @brief expireLater invokes delayed rule expiry on return to the main loop.
	 * <br><b>Locking: REQUIRES R</b>
	 */
	void            expireLater();

	/**
	 * @brief remove removes the Rule at nPos in the vector from the Manager.
	 * <br><b>Locking: REQUIRES RW</b>
	 *
	 * Note: Only rule vector locations after and equal to nPos are invalidited by calling this.
	 * Note: Caller needs to make sure the Rule is not accessed anymore after calling this, as it is
	 * given over to a QSharedPointer which will expire as soon as the GUI has removed the Rule.
	 *
	 * @param nPos  The RuleVectorPos where the Rule to be removed is located.
	 */
	void            remove( const RuleVectorPos nVectorPos );

	/**
	 * @brief isAgentDenied checks a user agent name against the list of
	 * [UserAgentRules](@ref UserAgentRule).
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param sUserAgent  The user agent string.
	 * @return <code>true</code> if the user agent is denied;
	 * <br><code>false</code> otherwise
	 */
	bool            isAgentDeniedInternal( const QString& sUserAgent );

	/**
	 * @brief isDenied checks a QueryHit against hash and content rules.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param pHit  The QueryHit to be checked.
	 * @return <code>true</code> if the hit is denied;
	 * <br><code>false</code> otherwise
	 */
	bool            isDenied( const QueryHit* const pHit );

	/**
	 * @brief isDenied checks a QueryHit name against the list of regular expression rules.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param lQuery    A list of all search keywords in the same order they have been entered in
	 * the edit box of the GUI.
	 * @param sContent  The content string/file name to be checked.
	 * @return <code>true</code> if the hit is denied;
	 * <br><code>false</code> otherwise
	 */
	bool            isDenied( const QList<QString>& lQuery, const QString& sContent );

	/**
	 * @brief isPrivate checks whether a given IP is located within one of the IP ranges designated
	 * for private use.
	 * <br><b>Locking: /</b>
	 *
	 * @param oAddress  The IP to be checked.
	 * @return <code>true</code> if the IP is within a private range;
	 * <br><code>false</code> otherwise
	 */
	bool            isPrivate( const EndPoint& oAddress );

#if SECURITY_DISABLE_IS_PRIVATE_OLD
	/**
	 * @brief isPrivateOld checks an IP the old way for whether it's private.
	 * <br><b>Locking: /</b>
	 *
	 * @param oAddress  The IP.
	 * @return <code>true</code> if the IP is within a private range;
	 * <br><code>false</code> otherwise
	 */
	bool            isPrivateOld( const EndPoint& oAddress );

	/**
	 * @brief isPrivateNew checks an IP the new way for whether it's private.
	 * <br><b>Locking: /</b>
	 *
	 * @param oAddress  The IP.
	 * @return <code>true</code> if the IP is within a private range;
	 * <br><code>false</code> otherwise
	 */
	bool            isPrivateNew( const EndPoint& oAddress );
#endif // SECURITY_DISABLE_IS_PRIVATE_OLD

	/**
	 * @brief findRangeForMerge allows to find the IPRangeRule containing or next to a given IP.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param oIp  The IP.
	 * @return the first range with <code>oAddress >= startIP()</code>, (e.g. the only range that
	 * might be containing the given IP);
	 * <br><code>m_vIPRanges.size()</code> if no such range exists.
	 */
	IPRangeVectorPos findRangeForMerging( const EndPoint& oAddress ) const;

	/**
	 * @brief findRangeMatch allows to find the range rule containing a given IP.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param oIp   The IP.
	 * @param nPos  A reference value that will be set to the RuleVectorPos within the vector.
	 * @return the IPRangeRule matching oAddress; <br><code>NULL</code> if no such Rule exists.
	 */
	IPRangeRule* findRangeMatch( const EndPoint& oAddress, IPRangeVectorPos& nPos ) const;
};
}

extern Security::Manager securityManager;

#endif // SECURITYMANAGER_H
