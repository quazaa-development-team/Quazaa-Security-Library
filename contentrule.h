/*
** contentrule.h
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

#ifndef CONTENTRULE_H
#define CONTENTRULE_H

#include "securerule.h"

namespace Security
{
// keyword (any/all) matching
class ContentRule : public Rule
{
private:
	bool        m_bSize;
	bool        m_bAll;
	QStringList m_lContent;

	typedef QStringList::const_iterator ListIterator;

public:
	ContentRule();
	Rule*   getCopy() const;

	bool    operator==(const Rule& pRule) const;

	bool    parseContent(const QString& sContent);

	void    setAll(bool all = true);
	bool    getAll() const;

	bool    match(const QString& sFileName) const; // called by  match(CQueryHit*)
	bool    match(const QueryHit* const pHit) const;

	void    toXML(QXmlStreamWriter& oXMLdocument) const;
};

}

#endif // CONTENTRULE_H
