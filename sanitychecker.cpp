/*
** sanitychecker.cpp
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

#include "sanitychecker.h"

using namespace Security;

SanityChecker::SanityChecker() :
	m_bNewRulesLoaded( false ),
	m_nPendingOperations( 0 ),
	m_bVerboose( false )
{
}

SanityChecker::~SanityChecker()
{
	clear();
}

bool SanityChecker::isNewlyDenied( const EndPoint& oAddress )
{
	if ( oAddress.isNull() )
	{
		return false;
	}

	// This should only be called if new rules have been loaded previously.
	Q_ASSERT( m_bNewRulesLoaded );

	RuleVectorPos n = 0;
	const RuleVectorPos nMax = m_vLoadedRules.size();

	Q_ASSERT( nMax );

	Rule* const * const pRules = &m_vLoadedRules[0];

	while ( n < nMax )
	{
		if ( pRules[n]->match( oAddress ) )
		{
			pRules[n]->count( common::getTNowUTC() );

			if ( pRules[n]->m_nAction == RuleAction::Deny )
			{
				return true;
			}
			else if ( pRules[n]->m_nAction == RuleAction::Accept )
			{
				return false;
			}
		}

		++n;
	}

	return false;
}

bool SanityChecker::isNewlyDenied( const QueryHit* const pHit, const QList<QString>& lQuery )
{
	if ( !pHit )
	{
		return false;
	}

	// This should only be called if new rules have been loaded previously.
	Q_ASSERT( m_bNewRulesLoaded );

	RuleVectorPos n = 0;
	const RuleVectorPos nMax = m_vLoadedRules.size();

	Q_ASSERT( nMax );

	Rule* const * const pRules = &m_vLoadedRules[0];

	while ( n < nMax )
	{
		if ( pRules[n]->match( pHit ) || pRules[n]->match( lQuery, pHit->m_sDescriptiveName ) )
		{
			pRules[n]->count( common::getTNowUTC() );

			if ( pRules[n]->m_nAction == RuleAction::Deny )
			{
				return true;
			}
			else if ( pRules[n]->m_nAction == RuleAction::Accept )
			{
				return false;
			}
		}

		++n;
	}

	return false;
}

void SanityChecker::sanityCheck()
{
	if ( m_bVerboose )
	{
		postLogMessage( LogSeverity::Debug, tr( "Initializing Sanity. " ), true );
	}

	if ( m_oRWLock.tryLockForWrite( 200 ) )
	{
		// This indicates that an error happend previously.
		Q_ASSERT( m_bNewRulesLoaded || m_vLoadedRules.empty() );

		bool bEmit = false;

		m_oQueueLock.lock();
		// If there are new rules to deal with.
		if ( m_lqNewRules.size() )
		{
			if ( !m_bNewRulesLoaded )
			{
				loadBatch();

				// Count how many "OK"s we need to get back.
				m_nPendingOperations = receivers( SIGNAL( beginSanityCheck() ) );

				// if there is anyone listening, start the sanity check
				if ( m_nPendingOperations )
				{
#ifdef _DEBUG
					// Failsafe mechanism in case there are massive problems somewhere else.
					m_idForceEoSC = signalQueue.push( this, "forceEndOfSanityCheck", 120 );
#endif
					bEmit = true;
				}
				else
				{
					clearBatch();
				}
			}
			else // other sanity check still in progress
			{
				// try again later
				if ( m_bVerboose )
					postLogMessage( LogSeverity::Debug,
									tr( "Other check still running. Trying again in 5 sec." ),
									true );
				signalQueue.push( this, "sanityCheck", 5 );
			}
		}

		m_oQueueLock.unlock();
		m_oRWLock.unlock();

		if ( bEmit )
			// Inform all other modules aber the necessity of a sanity check.
		{
			emit beginSanityCheck();
		}
	}
	else // We didn't get a write lock in a timely manner.
	{
		// try again later
		if ( m_bVerboose )
			postLogMessage( LogSeverity::Debug,
							tr( "Failed to obtain lock. Trying again in 5 sec." ),
							true );
		else
		{
			qDebug() << "[Security] Failed to obtain Sanity check lock. Trying again in 5 sec.";
		}
		signalQueue.push( this, "sanityCheck", 5 );
	}
}

void SanityChecker::sanityCheckPerformed()
{
	m_oRWLock.lockForWrite();

	Q_ASSERT( m_bNewRulesLoaded );
	Q_ASSERT( m_nPendingOperations > 0 );

	if ( --m_nPendingOperations )
	{
		if ( m_bVerboose )
			postLogMessage( LogSeverity::Debug, tr( "A component finished with sanity checking. " )
							+ tr( "Still waiting for %s other components to finish."
								).arg( m_nPendingOperations ), true );
	}
	else
	{
		if ( m_bVerboose )
			postLogMessage( LogSeverity::Debug, tr( "Sanity Check finished successfully. " ) +
							tr( "Starting cleanup now." ), true );

		clearBatch();
	}

	m_oRWLock.unlock();
}

#ifdef _DEBUG
void SanityChecker::forceEndOfSanityCheck()
{
	m_oRWLock.lockForWrite();

	if ( m_nPendingOperations )
	{
		QString sTmp = QObject::tr( "Sanity check aborted. Most probable reason: It took some " ) +
					   QObject::tr( "component longer than 2min to call sanityCheckPerformed() " ) +
					   QObject::tr( "after having recieved the signal performSanityCheck()." );
		postLogMessage( LogSeverity::Error, sTmp, true );
		Q_ASSERT( false );
	}

	m_nPendingOperations = 0;

	clearBatch();

	m_oRWLock.unlock();
}
#endif //_DEBUG

void SanityChecker::loadBatch()
{
	Q_ASSERT( !m_bNewRulesLoaded );
	Q_ASSERT( m_vLoadedRules.empty() );

	// there should be at least 1 new rule
	Q_ASSERT( m_lqNewRules.size() );

	Rule* pRule = NULL;

	while ( m_lqNewRules.size() )
	{
		pRule = m_lqNewRules.front();
		m_lqNewRules.pop();

		Q_ASSERT( pRule->type() && pRule->type() < RuleType::NoOfTypes );

		m_vLoadedRules.push_back( pRule );

		pRule = NULL;
	}

	m_bNewRulesLoaded = true;
}

void SanityChecker::clearBatch( bool bShutDown )
{
	Q_ASSERT( m_bNewRulesLoaded );
	Q_ASSERT( !m_nPendingOperations );

	// There should at least be one rule.
	Q_ASSERT( m_vLoadedRules.size() );

	const Rule* const * const pLoadedRules = &m_vLoadedRules[0];
	const RuleVectorPos nSize = m_vLoadedRules.size();
	for ( RuleVectorPos n = 0; n < nSize; ++n )
	{
		emit hit( pLoadedRules[n]->m_idUUID, pLoadedRules[n]->todayCount() );

		delete pLoadedRules[n];
	}

	m_vLoadedRules.clear();

#ifdef _DEBUG // use failsafe to abort sanity check only in debug version

	// don't access the signalQueue on shutdown, as it might already have been deleted
	if ( !m_idForceEoSC.isNull() && !bShutDown )
	{
		Q_ASSERT( signalQueue.pop( m_idForceEoSC ) );
		m_idForceEoSC = QUuid();
	}
#endif

	m_bNewRulesLoaded = false;
}

void SanityChecker::clear()
{
	m_oRWLock.lockForWrite();
	m_oQueueLock.lock();

	m_nPendingOperations = 0;

	if ( m_bNewRulesLoaded )
	{
		clearBatch( true );
	}

	while ( m_lqNewRules.size() )
	{
		delete m_lqNewRules.front();
		m_lqNewRules.pop();
	}

	m_oQueueLock.unlock();
	m_oRWLock.unlock();
}
