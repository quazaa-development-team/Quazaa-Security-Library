/*
** hashrule.h
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

#ifndef HASHRULE_H
#define HASHRULE_H

#include "securerule.h"

// Note: The locking information within the doxygen comments refers to the RW lock of the Security
//       Manager.

namespace Security
{
/* ============================================================================================== */
/* ========================================== HashRule ========================================== */
/* ============================================================================================== */
class HashRule : public Rule
{
private:
	HashSet m_vHashes;

	// m_sContent contains a space separated list of the urns of all hashes

public:
	HashRule();

	Rule*   getCopy() const;

	bool    parseContent( const QString& sContent );

	const HashSet& getHashes() const;
	void        setHashes( const HashSet& hashes );

	void    simplifyByHashPriority( quint8 nNumberOfHashes );

	bool    hashEquals( const HashRule& oRule ) const;

	bool    match( const QueryHit* const pHit ) const;
	bool    match(const HashSet& vHashes ) const; // called by match(CQueryHit*)

	void    toXML( QXmlStreamWriter& oXMLdocument ) const;
};

}

#endif // SECURERULE_H
