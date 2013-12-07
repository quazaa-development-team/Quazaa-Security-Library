/*
** sanitychecker.h
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

#ifndef SANITYCECKER_H
#define SANITYCECKER_H

#include <QObject>
#include <QReadWriteLock>

#include <vector>
#include <queue>

#include "externals.h"
#include "securerule.h"

namespace Security
{
class SanityCecker : public QObject
{
	Q_OBJECT

private:
	typedef std::vector< Rule*  > RuleVector;
	typedef RuleVector::size_type RuleVectorPos;

	// a queue for new rules to wait in
	typedef std::queue< Rule* > NewRulesQueue;

	mutable QReadWriteLock m_oRWLock;
	mutable QMutex         m_oQueueLock;

#ifdef _DEBUG // use failsafe to abort sanity check only in debug version
	QUuid           m_idForceEoSC;        // The signalQueue ID (force end of sanity check)
#endif

	// Used to manage newly added rules during sanity check
	RuleVector      m_vLoadedRules;
	NewRulesQueue   m_lqNewRules;

	// true if new rules for sanity check have been loaded.
	bool            m_bNewRulesLoaded;

	// Counts the number of program modules that still need to call back after having finished a
	// requested sanity check operation.
	unsigned short  m_nPendingOperations;

public:
	SanityCecker();
	~SanityCecker();

	/**
	 * @brief push writes a new rule to the queue for sanity checking.
	 * Locking: RW + R on the rule.
	 * @param pRule : the rule.
	 */
	inline void     push(Rule* pRule);

	/**
	 * @brief lockForWrite allocates a lock for reading.
	 */
	inline void     lockForRead();

	/**
	 * @brief unlock frees the read lock.
	 */
	inline void     unlock();

	/**
	 * @brief isNewlyDenied checks an IP against the list of loaded new security rules.
	 * Locking: REQUIRES R
	 * @param oAddress : the IP to be checked
	 * @return true if the IP is newly banned; false otherwise
	 */
	bool            isNewlyDenied(const CEndPoint& oAddress);

	/**
	 * @brief isNewlyDenied checks a hit against the list of loaded new security rules.
	 * Locking: REQUIRES R
	 * @param pHit : the QueryHit
	 * @param lQuery : the query string
	 * @return true if the hit is newly banned; false otherwise
	 */
	bool            isNewlyDenied(const CQueryHit* const pHit, const QList<QString>& lQuery);

signals:
	/**
	 * @brief beginSanityCheck informs all other application components about a sanity check.
	 */
	void            beginSanityCheck();

	/**
	 * @brief hit informs the security manager about the number of its the rules have recieved
	 * during the sanity check.
	 * @param ruleID : the rule GUI ID
	 * @param nCount : the number of hits
	 */
	void            hit(ID ruleID, uint nCount);

public slots:
	/**
	 * @brief sanityCheck triggers a system wide sanity check.
	 * Qt slot.
	 * The sanity check is delayed by 5s, if a write lock couldn't be aquired after 200ms.
	 * The sanity check is aborted if it takes longer than 2min to finish. (debug version only)
	 * Locking: QUEUE + RW
	 */
	void            sanityCheck();

	/**
	 * @brief sanityCheckPerformed is a call back slot.
	 * Qt slot. Must be notified by all listeners to the signal performSanityCheck() once they have
	 * completed their work.
	 * Locking: RW
	 */
	void            sanityCheckPerformed();

#ifdef _DEBUG // use failsafe to abort sanity check only in debug version
	/**
	 * @brief forceEndOfSanityCheck
	 * Qt slot. Aborts the currently running sanity check by clearing its rule list.
	 * For use in debug version only.
	 * Locking: RW
	 */
	void            forceEndOfSanityCheck();
#endif

private:
	/**
	 * @brief loadBatch loads a batch of waiting rules into the container used for sanity checking.
	 * Locking: REQUIRES QUEUE + REQUIRES RW
	 */
	void            loadBatch();

	/**
	 * @brief clearBatch unloads new rules from sanity check containers.
	 * Locking: REQUIRES RW
	 */
	void            clearBatch();

	/**
	 * @brief clear removes all rules.
	 * Locking: REQUIRES RW
	 */
	void            clear();
};

/**
 * @brief push writes a new rule to the queue for sanity checking.
 * Locking: QUEUE + REQUIRES R on the rule.
 * @param pRule : the rule.
 */
void SanityCecker::push(Rule* pRule)
{
	m_oQueueLock.lock();
	m_lqNewRules.push( pRule->getCopy() );
	m_oQueueLock.unlock();
}

/**
 * @brief lockForWrite allocates a lock for reading.
 */
void SanityCecker::lockForRead()
{
	m_oRWLock.lockForRead();
}

/**
 * @brief unlock frees the read lock.
 */
void SanityCecker::unlock()
{
	m_oRWLock.unlock();
}
}

#endif // SANITYCECKER_H
