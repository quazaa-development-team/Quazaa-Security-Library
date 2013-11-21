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

#include <QList>
#include <QString>

#include "securerule.h"

// contains everyting that does not fit into the other rule classes
class CContentRule : public CSecureRule
{
private:
	bool                m_bAll;
	QList< QString >    m_lContent;

	typedef QList< QString >::const_iterator CListIterator;

public:
	CContentRule();
	CSecureRule*    getCopy() const;

	bool            operator==(const CSecureRule& pRule) const;
	
	bool            parseContent(const QString& sContent);

	void            setAll(bool all = true);
	bool            getAll() const;

	bool            match(const QString& sFileName) const;
	bool            match(const CQueryHit* const pHit) const;

	void            toXML(QXmlStreamWriter& oXMLdocument) const;
};

}

#endif // CONTENTRULE_H