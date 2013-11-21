/*
** hashrule.h
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

#ifndef HASHRULE_H
#define HASHRULE_H

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "securerule.h"
#include "NetworkCore/Hashes/hash.h"

// Note: The locking information within the doxygen comments refers to the RW lock of the Security
//       Manager.

namespace Security
{
/* ============================================================================================== */
/* ========================================= CHashRule  ========================================= */
/* ============================================================================================== */
class CHashRule : public CSecureRule
{
private:
	QMap< CHash::Algorithm, CHash > m_Hashes;

public:
	CHashRule();
	
	CSecureRule*    getCopy() const;
	
	bool            parseContent(const QString& sContent);

	QList< CHash >  getHashes() const;
	void            setHashes(const QList< CHash >& hashes);

	bool            hashEquals(CHashRule& oRule) const;

	bool            match(const CQueryHit* const pHit) const;
	bool            match(const QList<CHash>& lHashes) const;

	void            toXML(QXmlStreamWriter& oXMLdocument) const;
};

}

#endif // SECURERULE_H
