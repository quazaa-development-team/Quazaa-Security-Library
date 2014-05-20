/*
** securerule.h
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

#ifndef SECURERULE_H
#define SECURERULE_H

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "externals.h"

namespace Security
{

/**
 * @brief ID is used to identify security rules in the GUI.
 */
typedef quint32 ID; // used for GUI updating

namespace RuleType
{
/**
 * @brief The Type enum describes the different Rule types.
 */
enum Type
{
	Undefined = 0, IPAddress = 1, IPAddressRange = 2, Country = 3, Hash = 4,
	RegularExpression = 5, UserAgent = 6, Content = 7, NoOfTypes = 8
};
}

namespace RuleAction
{
/**
 * @brief The Action enum describes the different possible Rule actions.
 */
enum Action
{
	None = 0, Accept = 1, Deny = 2, NoOfActions = 3
};
}

namespace RuleTime
{
/**
 * @brief The Time enum describes different Rule expiry times.
 */
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
	/**
	 * @brief m_nType is used to indicate the type of this Rule.
	 */
	// Type is critical to functionality and may not be changed externally.
	RuleType::Type  m_nType;

	/**
	 * @brief m_sContent contains a string representation of the Rule content for faster GUI
	 * accesses. Can be accessed from outside via getContentString().
	 */
	QString     m_sContent;

private:
	// Hit counters
	QAtomicInt  m_nToday;
	QAtomicInt  m_nTotal;

	quint32     m_tExpire;

	// mechanism for allocating GUI IDs
	static IDProvider<ID> m_oIDProvider;

public:
	/**
	 * @brief m_nAction stores the rule action (denied, allowed or none).
	 */
	RuleAction::Action  m_nAction;

	/**
	 * @brief m_idUUID stores the globally unique rule UUID.
	 */
	QUuid               m_idUUID;

	/**
	 * @brief m_nGUIID stores the rule GUI ID.
	 */
	ID                  m_nGUIID;

	/**
	 * @brief m_sComment stores the rule comment.
	 */
	QString             m_sComment;

	/**
	 * @brief m_bAutomatic stores whether this rule has been auto-generated or manually added.
	 */
	bool                m_bAutomatic;

public:
	/**
	 * @brief Rule constructs an empty security rule.
	 */
	Rule();
	virtual ~Rule();

protected:
	/**
	 * @brief Rule copy-constructs a security rule. This is protected in order to force the class
	 * user to conciously use getCopy to obtain duplicates.
	 *
	 * @param pRule The rule to copy.
	 */
	Rule( const Rule& pRule );

public:
	/**
	 * @brief getCopy allows to retrieve a copy of this Rule.
	 *
	 * @return A copy of this Rule.
	 */
	virtual Rule* getCopy() const = 0;

	/**
	 * @brief operator == can be used to compare this Rule to a second one. The comparison omits
	 * hit counters and GUI ID.
	 *
	 * @param pRule  The other Rule.
	 * @return <code>true</code> if both rules are equal;
	 * <br><code>false</code> otherwise
	 */
	virtual bool    operator==( const Rule& pRule ) const;

	/**
	 * @brief operator != can be used to compare this rule to a second one. The comparison omits
	 * hit counters and GUI ID.
	 *
	 * @param pRule  The other Rule.
	 * @return <code>false</code> if both rules are equal;
	 * <br><code>true</code> otherwise
	 */
	bool            operator!=( const Rule& pRule ) const;

	/**
	 * @brief parseContent parses a content string and incorporates it into the Rule.
	 *
	 * @param sContent  The content string.
	 * @return <code>true</code> if parsing was successful;
	 * <br><code>false</code> otherwise
	 */
	virtual bool    parseContent( const QString& sContent );

	/**
	 * @brief getContentString allows to access the content string. This is used mainly in the GUI.
	 * @return the content string
	 */
	QString         getContentString() const;

	/**
	 * @brief isExpired allows to check whether a Rule has expired.
	 *
	 * @param tNow      Indicates the current time in seconds since 1.1.1970 UTC
	 * @param bSession  Indicates whether this is the start of a new session.<br>
	 * In the case this is set to true, the return value for session ban rules will be true.
	 * @return <code>true</code> if the rule has expired;
	 * <br><code>false</code> otherwise
	 */
	bool    isExpired( quint32 tNow, bool bSession = false ) const;

	/**
	 * @brief setExpiryTime sets the expiry time of the Rule to the specified time.
	 *
	 * @param tExpire  The specified expiry time.
	 */
	void    setExpiryTime( const quint32 tExpire );

	/**
	 * @brief addExpiryTime adds a certain amount of of seconds to the expiry time, provided the
	 * Rule expiry time is not indefinite or the session.
	 *
	 * @param tAdd  The amount of seconds to add to the expiry time.
	 */
	void    addExpiryTime( const quint32 tAdd );

	/**
	 * @brief expiryTime allows to access the expiry time of a Rule.
	 * @return <code>0</code>: Indefinite; <br><code>1</code>: Session;<br>
	 * otherwise the expiry time in seconds since 1.1.1970 UTC.
	 */
	quint32 expiryTime() const;

	/**
	 * @brief mergeInto merges this Rule into pDestination.
	 *
	 * Takes the higher expiration time, m_bAutomatic if it is false, adds the today and total
	 * counters and modifies the comment string to indicate the merge. Overwrites the RuleAction of
	 * pDestination.
	 */
	void    mergeInto( Rule* pDestination ) const;

	/**
	 * @brief count increases the total and today hit counters by one each.
	 * <br><b>Requires Locking: /</b> (atomic op)
	 */
	void    count( uint nCount = 1 );

	/**
	 * @brief resetCount resets total and today hit counters to 0.
	 * <br><b>Requires Locking: /</b> (atomic op)
	 */
	void    resetCount();

	/**
	 * @brief todayCount allows to access the today hit counter.
	 * <br><b>Requires Locking: /</b> (atomic op)
	 *
	 * @return the value of the today hit counter
	 */
	quint32 todayCount() const;

	/**
	 * @brief totalCount allows to access the total hit counter.
	 * <br><b>Requires Locking: /</b> (atomic op)
	 *
	 * @return the value of the total hit counter
	 */
	quint32 totalCount() const;

	/**
	 * @brief loadTotalCount allows to set the value of the total hit counter.
	 * <br><b>Requires Locking: /</b> (atomic op)
	 *
	 * @param nTotal  The new value of the total hit counter.
	 */
	void    loadTotalCount( quint32 nTotal );

	/**
	 * @brief type allows to access the type of this rule.
	 * <br><b>Requires Locking: /</b>
	 *
	 * Note: The return value never changes after the constructor has finished executing.
	 * @return the rule type
	 */
	RuleType::Type  type() const;

	/**
	 * @brief match matches the address oAddress against the content of this Rule.
	 *
	 * @param oAddress  The address to match against this Rule.
	 * @return <code>true</code> if the oAddress is matched by the Rule;
	 * <br><code>false</code> otherwise
	 */
	virtual bool    match( const EndPoint& oAddress   ) const;

	/**
	 * @brief match matches the QueryHit pHit against the content of this Rule.
	 *
	 * @param pHit  The QueryHit.
	 * @return <code>true</code> if the QueryHit is matched by the Rule;
	 * <br><code>false</code> otherwise
	 */
	virtual bool    match( const QueryHit* const pHit ) const;

	/**
	 * @brief match matches the query hit file name sContent against this Rule.
	 *
	 * @param lQuery    A list of all search keywords in the same order they have been entered in
	 * the edit box of the GUI.
	 * @param sContent  The content string/file name to be checked.
	 * @return <code>true</code> if sContent is matched by the Rule;
	 * <br><code>false</code> otherwise
	 */
	virtual bool    match( const QList<QString>& lQuery, const QString& sContent ) const;

	/**
	 * @brief load retrieves a Rule from a QDataStream.
	 *
	 * @param fsFile    The filesteam to read the Rule from.
	 * @param nVersion  The data file version.
	 * @return the new Rule that has been read from the data stream
	 */
	static Rule*    load( QDataStream& fsFile, const int nVersion );

	/**
	 * @brief save writes the specified rule to the specified file.
	 *
	 * @param pRule    The Rule to save.
	 * @param oStream  The file stream to write to.
	 */
	static void     save( const Rule* const pRule, QDataStream& oStream );

	/**
	 * @brief fromXML reads a rule from a Security XML file.
	 *
	 * @param oXMLdocument  The XML document.
	 * @param nVersion      The XML document version.
	 * @return a new Rule that has been read from the XML document
	 */
	static Rule*    fromXML( QXmlStreamReader& oXMLdocument, float nVersion );

	/**
	 * @brief toXML allows to write this rule to a specified XML document.
	 *
	 * @param rXMLdocument  The XML document to write to.
	 */
	virtual void    toXML( QXmlStreamWriter& rXMLdocument ) const = 0;

protected:
	/**
	 * @brief toXML contains the default code for rule XML generation.
	 *
	 * @param rRule  The rule to write to the XML document.
	 * @param rXMLdocument The XML document to write to.
	 */
	static void     toXML( const Rule& rRule, QXmlStreamWriter& rXMLdocument );
};

}

#endif // SECURERULE_H
