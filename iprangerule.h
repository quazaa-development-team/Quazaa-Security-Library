/*
** iprangerule.h
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

#ifndef IPRANGERULE_H
#define IPRANGERULE_H

#include "securerule.h"

// Note: The locking information within the doxygen comments refers to the RW lock of the Security
//       Manager.

namespace Security
{
/* ============================================================================================== */
/* ======================================== CIPRangeRule ======================================== */
/* ============================================================================================== */
class IPRangeRule : public Rule
{
private:
	CEndPoint m_oStartIP;
	CEndPoint m_oEndIP;

public:
	IPRangeRule();

	Rule*           getCopy() const;

	bool            parseContent(const QString& sContent);

	CEndPoint       startIP() const;
	CEndPoint       endIP() const;

	IPRangeRule*    merge(IPRangeRule*& pOther);

	bool            match(const CEndPoint& oAddress) const;
	bool            contains(const CEndPoint& oAddress) const;

	void            toXML(QXmlStreamWriter& oXMLdocument) const;
};

}
#endif // IPRANGERULE_H
