/*
** regexprule.h
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

#ifndef REGEXPRULE_H
#define REGEXPRULE_H

#include "securerule.h"

#if QT_VERSION >= 0x050000
#  include <QRegularExpression>
#else
#  include <QRegExp>
#endif

// Note: The locking information within the doxygen comments refers to the RW lock of the Security
//       Manager.

namespace Security
{
/* ============================================================================================== */
/* ======================================== CRegExpRule  ======================================== */
/* ============================================================================================== */
class RegularExpressionRule : public Rule
{
private:
	// There are two kinds of rules:
	// 1. Those which contain <_>, <1>...<9> or <> (e.g. special elements)
	// 2. All other rules.
	bool                m_bSpecialElements; // contains special elements

#if QT_VERSION >= 0x050000
	QRegularExpression  m_regularExpressionContent;
#else
	QRegExp             m_regExpContent;
#endif

public:
	RegularExpressionRule();
	Rule*       getCopy() const;

	bool        operator==( const Rule& pRule ) const;

	bool        parseContent( const QString& sContent );

	bool        match( const QList<QString>& lQuery, const QString& sContent ) const;
	void        toXML( QXmlStreamWriter& oXMLdocument ) const;

private:
	static bool replace( QString& sReplace, const QList<QString>& lQuery, quint8& nCurrent );
};

}

#endif // REGEXPRULE_H
