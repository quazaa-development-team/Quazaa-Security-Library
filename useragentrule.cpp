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

UserAgentRule::UserAgentRule()
{
	m_nType = RuleType::UserAgent;
	m_bRegExp  = false;
}

Rule* UserAgentRule::getCopy() const
{
	return new UserAgentRule( *this );
}

bool UserAgentRule::operator==( const Rule& pRule ) const
{
	return Rule::operator==( pRule ) && m_bRegExp == ( ( UserAgentRule* )&pRule )->m_bRegExp;
}

bool UserAgentRule::parseContent( const QString& sContent )
{
	if ( m_bRegExp )
	{
#if QT_VERSION >= 0x050000
		QRegularExpression exp = QRegularExpression( sContent.trimmed() );

		if ( exp.isValid() )
		{
			m_sContent = sContent.trimmed();
			m_regularExpressionContent = exp;
		}
		else
		{
			return false;
		}
#else
		QRegExp exp = QRegExp( sContent.trimmed() );

		if ( exp.isValid() )
		{
			m_sContent = sContent.trimmed();
			m_regExpContent = exp;
		}
		else
		{
			return false;
		}
#endif
	}
	else
	{
		m_sContent = sContent.trimmed();
	}

	return true;
}

void UserAgentRule::setRegExp( bool bRegExp )
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

bool UserAgentRule::getRegExp() const
{
	return m_bRegExp;
}

bool UserAgentRule::match( const QString& sUserAgent ) const
{
	Q_ASSERT( m_nType == RuleType::UserAgent );

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

void UserAgentRule::toXML( QXmlStreamWriter& oXMLdocument ) const
{
	Q_ASSERT( m_nType == RuleType::UserAgent );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "agent" );

	if ( m_bRegExp )
	{
		oXMLdocument.writeAttribute( "match", "regexp" );
	}
	else
	{
		oXMLdocument.writeAttribute( "match", "list" );
	}

	oXMLdocument.writeAttribute( "content", getContentString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
