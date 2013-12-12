/*
** securerule.h
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

#ifndef SECURERULE_H
#define SECURERULE_H

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "externals.h"

// Note: The locking information within the doxygen comments refers to the RW lock of the Security
//       Manager.

namespace Security
{

typedef quint32 ID; // used for GUI updating

namespace RuleType
{
	enum Type
	{
		Undefined = 0, IPAddress = 1, IPAddressRange = 2, Country = 3, Hash = 4,
		RegularExpression = 5, UserAgent = 6, Content = 7, NoOfTypes = 8
	};
}

namespace RuleAction
{
	enum Action
	{
		None = 0, Accept = 1, Deny = 2, NoOfActions = 3
	};
}

namespace RuleTime
{
	enum Time
	{
		Forever = 0, Session = 1, FiveMinutes = 300, ThirtyMinutes = 1800, TwoHours = 7200,
		SixHours = 21600, TwelveHours = 42300, Day = 86400, Week = 604800, Month = 2592000,
		SixMonths = 15552000
	};
}

class Rule
{
protected:
	// Type is critical to functionality and may not be changed externally.
	RuleType::Type  m_nType;

	// Contains a string representation of the rule content for faster GUI accesses.
	// Can be accessed via getContentString().
	QString     m_sContent;

private:
	// Hit counters
	QAtomicInt  m_nToday;
	QAtomicInt  m_nTotal;

	quint32     m_tExpire;

	// mechanism for allocating GUI IDs
	static ID           m_nLastID;
	static QMutex       m_oIDLock;
	static std::set<ID> m_lsIDCheck;

public:
	RuleAction::Action  m_nAction;
	QUuid               m_idUUID;
	ID                  m_nGUIID;    // used for GUI updating
	QString             m_sComment;
	bool                m_bAutomatic;

public:
	// Construction / Destruction
	Rule();
	Rule(const Rule& pRule);
	virtual ~Rule();

	// Returns a copy of the current rule. Note that this copy does not contain
	// any information on pointers registered to the original CSecureRule object.
	virtual Rule* getCopy() const;

	// Operators
	virtual bool    operator==(const Rule& pRule) const;
	bool            operator!=(const Rule& pRule) const;

	virtual bool    parseContent(const QString& sContent);
	QString         getContentString() const;

	bool    isExpired(quint32 tNow, bool bSession = false) const;
	void    setExpiryTime(const quint32 tExpire);
	void    addExpiryTime(const quint32 tAdd);
	quint32 getExpiryTime() const;

	void    mergeInto(Rule* pDestination);

	// Hit count control
	void    count();
	void    resetCount();
	quint32 getTodayCount() const;
	quint32 getTotalCount() const;
	void    loadTotalCount(quint32 nTotal);

	// get the rule type
	RuleType::Type  type() const;

	// Check content for hits
	virtual bool    match(const CEndPoint& oAddress) const;
	//virtual bool    match(const QString& sContent) const;
	virtual bool    match(const CQueryHit* const pHit) const;
	virtual bool    match(const QList<QString>& lQuery, const QString& sContent) const;

	// Read/write rule from/to file
	static void     load(Rule*& pRule, QDataStream& fsFile, const int nVersion);
	static void     save(const Rule* const pRule, QDataStream& oStream);

	// XML Import/Export functionality
	static Rule*    fromXML(QXmlStreamReader& oXMLdocument, float nVersion);
	virtual void    toXML(QXmlStreamWriter& oXMLdocument) const;

protected:
	// Contains default code for XML generation.
	static void     toXML(const Rule& oRule, QXmlStreamWriter& oXMLdocument);

	static ID generateID();
	static void releaseID(ID nID);
};

}

#endif // SECURERULE_H
