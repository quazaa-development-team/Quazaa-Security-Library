/*
** iprangerule.h
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

#ifndef IPRANGERULE_H
#define IPRANGERULE_H

#include "securerule.h"

namespace Security
{

/**
 * @brief The IPRangeRule class manages IP matching against IP ranges.
 */
class IPRangeRule : public Rule
{
private:
	EndPoint m_oStartIP;
	EndPoint m_oEndIP;

public:
	IPRangeRule();

	Rule*           getCopy() const;

	bool            parseContent( const QString& sContent );

	EndPoint        startIP() const;
	EndPoint        endIP() const;

	/**
	 * @brief merge merges pOther into this rule.
	 *
	 * Note that this changes only the ranges of this Rule.
	 * Note also that the caller needs to make sure for something of this rule to remain after
	 * merging. In case this rule is split into two, the second half is returned as a new rule which
	 * needs to be added by the Manager.
	 *
	 * @param pOther  The Rule to merge into this one; Set to <code>NULL</code> if superfluous after
	 * merging.
	 * @return <code>NULL</code> except if <code>pOther</code> is contained within this rule - in
	 * which case this Rule is split into two parts and the second of these parts (representing the
	 * part of this rule's range after the range of pOther) is returned.
	 */
	IPRangeRule*    merge( IPRangeRule*& pOther );

	bool            match( const EndPoint& oAddress ) const;
	bool            contains( const EndPoint& oAddress ) const;

	void            toXML( QXmlStreamWriter& oXMLdocument ) const;
};

}
#endif // IPRANGERULE_H
