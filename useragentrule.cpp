/*
** useragentrule.cpp
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

#include "useragentrule.h"

#include "debug_new.h"

using namespace Security;

CUserAgentRule::CUserAgentRule()
{
	m_nType = srContentUserAgent;
	m_bRegExp  = false;
}

bool CUserAgentRule::operator==(const CSecureRule& pRule) const
{
	return CSecureRule::operator==( pRule ) && m_bRegExp == ((CUserAgentRule*)&pRule)->m_bRegExp;
}

void CUserAgentRule::setRegExp(bool bRegExp)
{
	m_bRegExp = bRegExp;

	if ( m_bRegExp )
	{
#if QT_VERSION >= 0x050000
		m_regularExpressionContent = QRegularExpression( m_sContent );
#else
		m_regExpContent = QRegExp( m_sContent );
#endif
	}
}

bool CUserAgentRule::parseContent(const QString& sContent)
{
	m_sContent = sContent.trimmed();

	if ( m_bRegExp )
	{
#if QT_VERSION >= 0x050000
		m_regularExpressionContent = QRegularExpression( m_sContent );
#else
		m_regExpContent = QRegExp( m_sContent );
#endif
	}

	return true;
}

bool CUserAgentRule::match(const QString& sUserAgent) const
{
	Q_ASSERT( m_nType == srContentUserAgent );

	if ( m_bRegExp )
	{
#if QT_VERSION >= 0x050000
		return m_regularExpressionContent.match( sUserAgent ).hasMatch();
#else
		return m_regExpContent.exactMatch( sUserAgent );
#endif
	}
	else
	{
		return sUserAgent.contains( m_sContent, Qt::CaseInsensitive );
	}

	return false;
}

bool CUserAgentRule::partialMatch(const QString& sUserAgent) const
{
	Q_ASSERT( m_nType == srContentUserAgent );
	return sUserAgent.contains( m_sContent, Qt::CaseInsensitive );
}

void CUserAgentRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == srContentUserAgent );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "agent" );

	if( m_bRegExp )
	{
		oXMLdocument.writeAttribute( "match", "regexp" );
	}
	else
	{
		oXMLdocument.writeAttribute( "match", "list" );
	}

	oXMLdocument.writeAttribute( "content", getContentString() );

	CSecureRule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}

CSecureRule* CUserAgentRule::getCopy() const
{
	return new CUserAgentRule( *this );
}

bool CUserAgentRule::getRegExp() const
{
	return m_bRegExp;
}