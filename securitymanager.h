/*
** $Id$
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

#ifndef SECURITYMANAGER_H
#define SECURITYMANAGER_H

#include <list>
#include <map>
#include <queue>
#include <set>

#include "securerule.h"
#include "commonfunctions.h"

// Enable/disable GeoIP support of the library.
#define SECURITY_ENABLE_GEOIP 0

// Increment this if there have been made changes to the way of storing security rules.
#define SECURITY_CODE_VERSION	0
// History:
// 0 - Initial implementation

// TODO: Use UTC times accross the security manager.
// DODO: Add quint16 GUI ID to rules and update GUI only when there is a change to the rule.
// TODO: Enable/disable this according to the visibility within the GUI
// TODO: m_nMaxUnsavedRules >> Settings
// TODO: add log calls + defines to enable/disable

namespace Security
{

class CSecurity : public QObject
{
	Q_OBJECT
	/* ================================================================ */
	/* ========================== Attributes ========================== */
	/* ================================================================ */
public:
	static const QString xmlns;
	static const char* ruleInfoSignal;

	mutable QReadWriteLock m_pRWLock;

	typedef enum
	{
		banSession, ban5Mins, ban30Mins, ban2Hours, banWeek, banMonth, banForever
	} BanLength;

private:
	typedef std::pair< uint, CHashRule* > CHashPair;

	typedef std::list< CSecureRule*  > CSecurityRuleList;
	typedef std::list< CIPRangeRule* > CIPRangeRuleList;
	typedef std::list< CRegExpRule*  > CRegExpRuleList;
	typedef std::list< CContentRule* > CContentRuleList;

	typedef std::queue< CSecureRule* > CNewRulesQueue;

	typedef std::set< uint > CMissCache;

	typedef std::map< uint, CIPRule*           > CAddressRuleMap;
#if SECURITY_ENABLE_GEOIP
	typedef std::map< QString, CCountryRule*   > CCountryRuleMap;
#endif // SECURITY_ENABLE_GEOIP
	typedef std::map< QString, CUserAgentRule* > CUserAgentRuleMap;

	// Note: Using a multimap eliminates eventual problems of hash
	// collisions caused by weaker hashes like MD5 for example.
	typedef std::multimap< uint, CHashRule* > CHashRuleMap;

	typedef CSecurityRuleList::const_iterator CIterator;

	// contains all rules
	CSecurityRuleList   m_Rules;

	// Used to manage newly added rules during sanity check
	CSecurityRuleList   m_loadedAddressRules;
	CNewRulesQueue      m_newAddressRules;
	CSecurityRuleList   m_loadedHitRules;
	CNewRulesQueue      m_newHitRules;

	// IP rule miss cache
	CMissCache          m_Cache;

	// single IP blocking rules
	CAddressRuleMap     m_IPs;

	// multiple IP blocking rules
	CIPRangeRuleList    m_IPRanges;

#if SECURITY_ENABLE_GEOIP
	// country rules
	CCountryRuleMap     m_Countries;
#endif // SECURITY_ENABLE_GEOIP

	// hash rules
	CHashRuleMap        m_Hashes;

	// all other content rules
	CContentRuleList    m_Contents;

	// RegExp rules
	CRegExpRuleList     m_RegExpressions;

	// User agent rules
	CUserAgentRuleMap   m_UserAgents;

	// Security manager settings
	QString             m_sDataPath;                // Path to the security.dat file
	bool                m_bLogIPCheckHits;          // Post log message on IsDenied( QHostAdress ) call
	quint64             m_tRuleExpiryInterval;      // Check the security manager for expired hosts each x milliseconds
	quint64             m_tMissCacheExpiryInterval; // Clear the miss cache each x ms

	// Timer IDs
	QUuid               m_idRuleExpiry;       // The ID of the signalQueue object.
	QUuid               m_idMissCacheExpiry;  // The ID of the signalQueue object.

	// Other
	bool                m_bUseMissCache;
	bool                m_bIsLoading;         // true during import operations. Used to avoid unnecessary GUI updates.
	bool                m_bNewRulesLoaded;    // true if new rules for sanity check have been loaded.
	unsigned short      m_nPendingOperations; // Counts the number of program modules that still need to call back after having finished a requested sanity check operation.

	quint16             m_nMaxUnsavedRules;   // maximal number of unsaved rules to tolerate before forcing save
	mutable QAtomicInt  m_nUnsaved;           // count of unsaved rules

	bool                m_bDenyPolicy;
	// m_bDenyPolicy == false : everything but specifically blocked IPs is allowed (default)
	// m_bDenyPolicy == true  : everything but specifically allowed IPs is rejected
	// Note that the default policy is only applied to IP related rules, as everything
	// else does not make any sense.

public:
	/* ================================================================ */
	/* ========================= Construction ========================= */
	/* ================================================================ */
	CSecurity();
	~CSecurity();

	/* ================================================================ */
	/* ========================== Operations ========================== */
	/* ================================================================ */
	inline quint32  getCount() const;

	inline bool     denyPolicy() const;
	void            setDenyPolicy(bool bDenyPolicy);

	bool            check(const CSecureRule* const pRule) const;
	void            add(CSecureRule* pRule);
	// Use bLockRequired to enable/disable locking inside function.
	inline void     remove(CSecureRule* pRule, bool bLockRequired = true);
	void            clear();

	void            ban(const QHostAddress& oAddress, BanLength nBanLength, bool bMessage = true, const QString& sComment = "");
//	void            ban(const CFile& oFile, BanLength nBanLength, bool bMessage = true, const QString& sComment = "");

	// Methods used during sanity check
	bool            isNewlyDenied(const CEndPoint& oAddress);
	bool            isNewlyDenied(const CQueryHit* pHit, const QList<QString>& lQuery);

	bool            isDenied(const CEndPoint& oAddress, const QString &source = "Unknown");
	// This does not check for the hit IP to avoid double checking.
	bool            isDenied(const CQueryHit* const pHit, const QList<QString>& lQuery);

	// Checks the user agent to see if it's a GPL breaker, or other trouble-maker
	// We don't ban them, but also don't offer leaf slots to them.
	bool            isClientBad(const QString& sUserAgent) const;

	// Checks the user agent to see if it's a leecher client, or other banned client
	// Test new releases, and remove block if/when they are fixed.
	// Includes check of agent blocklist & agent security rules.
	bool            isAgentBlocked(const QString& sUserAgent);

	// Check the evil's G1/G2 vendor code
	bool            isVendorBlocked(const QString& sVendor) const;

	// Export/Import/Load/Save handlers
	bool            start(); // connects signals etc.
	bool            stop(); // makes the Security Manager ready for destruction
	bool            load();
	bool            save(bool bForceSaving = false) const;
	static void     writeToFile(const void* const pManager, QFile& oFile); // used by save()
	bool            import(const QString& sPath);
	bool            toXML(const QString& sPath) const;
	bool            fromXML(const QString& sPath);

	// Allows for external callers to find out about how many listeners there
	// are to the Security Manager Signals.
	int             receivers(const char* signal) const;

	inline quint32  getTNowUTC();

signals:
	void            ruleAdded(CSecureRule* pRule);
	void            ruleRemoved(QSharedPointer<CSecureRule> pRule);

	void            ruleInfo(CSecureRule* pRule);

	void            securityHit();

	// This is used to inform other modules that a system wide sanity check has become necessary.
	void            performSanityCheck();

public slots:
	// Trigger this to let the Security Manager emit all rules
	void            requestRuleList();

	// Start system wide sanity check
	void            sanityCheck();
	// This slot must be triggered by all listeners to performSanityCheck() once they have completed their work.
	void            sanityCheckPerformed();
	// Aborts all currently running sanity checks by clearing their rule lists.
	void            forceEndOfSanityCheck();

	void            expire();
	void            missCacheClear();

	// Trigger this slot to inform the security manager about changes in the security settings.
	void            settingsChanged();

private:
	// Sanity check helper methods
	void            loadNewRules();
	void            clearNewRules();

	bool            load(QString sPath);

	// this returns the first rule found. Note that there might be others, too.
	CIterator       getHash(const QList< CHash >& hashes) const;
	CIterator       getUUID(const QUuid& oUUID) const;

	void            remove(CIterator i);

	bool            isAgentDenied(const QString& strUserAgent);

	void            missCacheAdd(const uint& nIP);
	void            missCacheClear(bool bRefreshInterval);
	void            evaluateCacheUsage();				// determines whether it is logical to use the cache or not

	bool            isDenied(const QString& sContent);
	bool            isDenied(const CQueryHit* const pHit);
	bool            isDenied(const QList<QString>& lQuery, const QString& sContent);

	inline void     hit(CSecureRule *pRule);

	inline CSecurityRuleList::iterator getRWIterator(CIterator const_it);
};

quint32 CSecurity::getCount() const
{
	return (quint32)m_Rules.size();
}

bool CSecurity::denyPolicy() const
{
	return m_bDenyPolicy;
}

quint32 CSecurity::getTNowUTC()
{
	return QDateTime::currentDateTimeUtc().toTime_t();
}

void CSecurity::remove(CSecureRule* pRule, bool bLockRequired)
{
	if ( !pRule )
		return;

	if ( bLockRequired )
		m_pRWLock.lockForWrite();

	remove( getUUID( pRule->m_oUUID ) );

	if ( bLockRequired )
		m_pRWLock.unlock();
}

void CSecurity::hit(CSecureRule* pRule)
{
	pRule->count();
	emit securityHit();
}

CSecurity::CSecurityRuleList::iterator CSecurity::getRWIterator(CIterator const_it)
{
	CSecurityRuleList::iterator i = m_Rules.begin();
	CIterator const_begin = m_Rules.begin();
	int nDistance = std::distance< CIterator >( const_begin, const_it );
	std::advance( i, nDistance );
	return i;
}

}

extern Security::CSecurity securityManager;

#endif // SECURITYMANAGER_H
