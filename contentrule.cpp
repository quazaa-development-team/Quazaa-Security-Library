/*
** contentrule.cpp
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

#include "contentrule.h"

#include "debug_new.h"

#if QT_VERSION >= 0x050000
#  include <QRegularExpression>
#else
#  include <QRegExp>
#endif

using namespace Security;

ContentRule::ContentRule() :
	m_bSize( false ),
	m_bAll( true )
{
	m_nType = RuleType::Content;
}

Rule* ContentRule::getCopy() const
{
	return new ContentRule( *this );
}

bool ContentRule::operator==( const Rule& pRule ) const
{
	return Rule::operator==( pRule ) && m_bAll == ( ( ContentRule* )&pRule )->m_bAll;
}

bool ContentRule::parseContent( const QString& sContent )
{
	Q_ASSERT( m_nType == RuleType::Content );

	QString sWork = sContent;
	sWork.replace( '\t', ' ' );

	QStringList lWork = sWork.split( ' ', QString::SkipEmptyParts );

	if ( !lWork.isEmpty() )
	{
		m_lContent.clear();
		m_lContent = lWork;
		m_bSize = false;

		QString sFilter = "^size:\\w+:\\d+$"; // match anything like size:<extension>:<filesize>
#if QT_VERSION >= 0x050000
		QRegularExpression oSizeFilter( sFilter );
#else
		QRegExp oSizeFilter( sFilter );
#endif

		m_sContent.clear();
		for ( ListIterator i = m_lContent.begin() ; i != m_lContent.end() ; ++i )
		{
#if QT_VERSION >= 0x050000
			if ( oSizeFilter.match( *i ).hasMatch() )
#else
			if ( oSizeFilter.exactMatch( *i ) )
#endif
			{
				m_bSize = true;
			}
			m_sContent += *i + " ";
		}

		// remove trailing whitespace
		m_sContent = m_sContent.trimmed();
		return true;
	}
	return false;
}

void ContentRule::setAll( bool all )
{
	m_bAll = all;
}

bool ContentRule::getAll() const
{
	return m_bAll;
}

bool ContentRule::match( const QString& sFileName ) const
{
	for ( ListIterator i = m_lContent.begin() ; i != m_lContent.end() ; ++i )
	{
		bool bFound = sFileName.indexOf( *i ) != -1;

		if ( bFound && !m_bAll )
		{
			return true;
		}
		else if ( !bFound && m_bAll )
		{
			return false;
		}
	}

	if ( m_bAll )
	{
		return true;
	}

	return false;
}

bool ContentRule::match( const QueryHit* const pHit ) const
{
	if ( !pHit )
	{
		return false;
	}

	QString sFileName = pHit->m_sDescriptiveName;

	qint32 index;
	if ( m_bSize && ( ( index = sFileName.lastIndexOf( '.' ) + 1 ) ) )
	{
		QString sExt = sFileName.mid( index );
		QString sExtFileSize = "size:%1:%2";
		sExtFileSize = sExtFileSize.arg( sExt, QString::number( pHit->m_nObjectSize ) );
		if ( match( sExtFileSize ) )
		{
			return true;
		}
	}

	return match( sFileName );
}

void ContentRule::toXML( QXmlStreamWriter& oXMLdocument ) const
{
	Q_ASSERT( m_nType == RuleType::Content );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "content" );

	if ( m_bAll )
	{
		oXMLdocument.writeAttribute( "match", "all" );
	}
	else
	{
		oXMLdocument.writeAttribute( "match", "any" );
	}

	oXMLdocument.writeAttribute( "content", getContentString() );

	Rule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
