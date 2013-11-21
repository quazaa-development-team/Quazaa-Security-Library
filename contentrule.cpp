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

using namespace Security;

CContentRule::CContentRule()
{
	m_nType = srContentText;
	m_bAll = true;
}

CSecureRule* CContentRule::getCopy() const
{
	return new CContentRule( *this );
}

bool CContentRule::operator==(const CSecureRule& pRule) const
{
	return CSecureRule::operator==( pRule ) && m_bAll == ((CContentRule*)&pRule)->m_bAll;
}

bool CContentRule::parseContent(const QString& sContent)
{
	Q_ASSERT( m_nType == srContentText );

	QString sWork = sContent;
	sWork.replace( '\t', ' ' );

	m_lContent.clear();

	QString tmp;

	QList< QString > lWork;

	while ( !sWork.isEmpty() )
	{
		sWork = sWork.trimmed();
		int index = sWork.indexOf( ' ' );
		tmp = ( index != -1 ) ? sWork.left( index ) : sWork;
		if ( !tmp.isEmpty() )
			lWork.push_back( tmp );
		sWork = sWork.mid( ( index != -1 ) ? index : 0 );
	}

	if ( !lWork.isEmpty() )
	{
		m_lContent = lWork;

		m_sContent.clear();
		for ( CListIterator i = m_lContent.begin() ; i != m_lContent.end() ; i++ )
		{
			m_sContent += *i;
		}
		return true;
	}
	return false;
}

void CContentRule::setAll(bool all)
{
	m_bAll = all;
}

bool CContentRule::getAll() const
{
	return m_bAll;
}

bool CContentRule::match(const QString& sFileName) const
{
	for ( CListIterator i = m_lContent.begin() ; i != m_lContent.end() ; i++ )
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
		return true;

	return false;
}

bool CContentRule::match(const CQueryHit* const pHit) const
{
	if ( !pHit )
		return false;

	QString sFileName = pHit->m_sDescriptiveName;
	qint32 index = sFileName.lastIndexOf( '.' );
	if ( index != -1 )
	{
		QString sExt = sFileName.mid( index );
		QString sExtFileSize = "size:%1:%2";
		sExtFileSize.arg( sExt, QString::number( pHit->m_nObjectSize ) );
		if ( match( sExtFileSize ) )
			return true;
	}

	return match( sFileName );
}

void CContentRule::toXML(QXmlStreamWriter& oXMLdocument) const
{
	Q_ASSERT( m_nType == srContentText );

	oXMLdocument.writeStartElement( "rule" );

	oXMLdocument.writeAttribute( "type", "content" );

	if( m_bAll )
	{
		oXMLdocument.writeAttribute( "match", "all" );
	}
	else
	{
		oXMLdocument.writeAttribute( "match", "any" );
	}

	oXMLdocument.writeAttribute( "content", getContentString() );

	CSecureRule::toXML( *this, oXMLdocument );

	oXMLdocument.writeEndElement();
}
