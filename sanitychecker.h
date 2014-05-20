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

#ifndef SANITYCHECKER_H
#define SANITYCHECKER_H

#include <QObject>
#include <QReadWriteLock>

#include <vector>
#include <queue>

#include "externals.h"
#include "securerule.h"

namespace Security
{

/**
 * @brief The SanityCecker class manages coordinating the rechecking of the entire application in
 * the case of rule additions.
 */
class SanityChecker : public QObject
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

	bool            m_bVerboose;

public:
	/**
	 * @brief SanityCecker constructs an empty SanityCecker.
	 */
	SanityChecker();
	~SanityChecker();

	/**
	 * @brief push adds a new rule to the queue for sanity checking.
	 * <br><b>Locking: QUEUE + REQUIRES R on the rule</b>
	 *
	 * @param pRule : the rule.
	 */
	inline void     push( Rule* pRule );

	/**
	 * @brief lockForWrite allocates a lock for reading.
	 */
	inline void     lockForRead();

	/**
	 * @brief unlock unlocks the read lock.
	 */
	inline void     unlock();

	/**
	 * @brief isNewlyDenied checks an IP against the list of loaded new security rules.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param oAddress  The IP to be checked
	 * @return <code>true</code> if the IP is newly banned;
	 * <br><code>false</code> otherwise
	 */
	bool            isNewlyDenied( const EndPoint& oAddress );

	/**
	 * @brief isNewlyDenied checks a hit against the list of loaded new security rules.
	 * <br><b>Locking: REQUIRES R</b>
	 *
	 * @param pHit    The QueryHit
	 * @param lQuery  The query string
	 * @return <code>true</code> if the IP is newly banned;
	 * <br><code>false</code> otherwise
	 */
	bool            isNewlyDenied( const QueryHit* const pHit, const QList<QString>& lQuery );

signals:
	/**
	 * @brief beginSanityCheck informs all other application components about a sanity check.
	 */
	void            beginSanityCheck();

	/**
	 * @brief hit informs the security manager about the number of its the rules have recieved
	 * during the sanity check.
	 *
	 * @param ruleID  The rule GUI ID
	 * @param nCount  The number of hits
	 */
	void            hit( QUuid ruleID, uint nCount );

public slots:
	/**
	 * @brief sanityCheck triggers a system wide sanity check.
	 * <br><b>Locking: QUEUE + RW</b>
	 *
	 * The sanity check is delayed by 5s, if a write lock couldn't be aquired after 200ms.<br>
	 * The sanity check is aborted if it takes longer than 2min to finish. (debug version only)
	 */
	void            sanityCheck();

	/**
	 * @brief sanityCheckPerformed is a call-back slot.
	 * <br><b>Locking: RW</b>
	 *
	 * Note: Must be notified by all listeners to the signal performSanityCheck() once they have
	 * completed their work.
	 */
	void            sanityCheckPerformed();

#ifdef _DEBUG // use failsafe to abort sanity check only in debug version
	/**
	 * @brief forceEndOfSanityCheck aborts the currently running sanity check by clearing its rule
	 * list.
	 * <br><b>Locking: RW</b>
	 *
	 * Note: For useage in debug version only.
	 */
	void            forceEndOfSanityCheck();
#endif

private:
	/**
	 * @brief loadBatch loads a batch of waiting rules into the container used for sanity checking.
	 * <br><b>Locking: REQUIRES QUEUE + REQUIRES RW</b>
	 */
	void            loadBatch();

	/**
	 * @brief clearBatch unloads the new rules from sanity check containers.
	 * <br><b>Locking: REQUIRES RW</b>
	 */
	void            clearBatch( bool bShutDown = false );

	/**
	 * @brief clear removes all rules. Only to be called on shutdown.
	 * <br><b>Locking: REQUIRES RW</b>
	 */
	void            clear();
};

void SanityChecker::push( Rule* pRule )
{
	m_oQueueLock.lock();
	m_lqNewRules.push( pRule->getCopy() );
	m_oQueueLock.unlock();
}

void SanityChecker::lockForRead()
{
	m_oRWLock.lockForRead();
}

void SanityChecker::unlock()
{
	m_oRWLock.unlock();
}
}

#endif // SANITYCHECKER_H
