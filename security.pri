#
# security.pri
#
# Copyright © Quazaaa Development Team, 2009-2013.
# This file is part of QUAZAA (quazaa.sourceforge.net)
#
# Quazaa is free software; this file may be used under the terms of the GNU
# General Public License version 3.0 or later or later as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.
#
# Quazaa is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Please review the following information to ensure the GNU General Public
# License version 3.0 requirements will be met:
# http://www.gnu.org/copyleft/gpl.html.
#
# You should have received a copy of the GNU General Public License version
# 3.0 along with Quazaa; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

QT_VERSION = $$[QT_VERSION]
QT_VERSION = $$split(QT_VERSION, ".")

INCLUDEPATH += $$PWD

# Headers
HEADERS += \
		$$PWD/contentrule.h \
		$$PWD/countryrule.h \
		$$PWD/externals.h \
		$$PWD/hashrule.h \
		$$PWD/iprangerule.h \
		$$PWD/iprule.h \
		$$PWD/misscache.h \
		$$PWD/regexprule.h \
		$$PWD/sanitychecker.h \
		$$PWD/securerule.h \
		$$PWD/securitymanager.h \
		$$PWD/useragentrule.h

# Sources
SOURCES += \
		$$PWD/contentrule.cpp \
		$$PWD/countryrule.cpp \
		$$PWD/externals.cpp \
		$$PWD/hashrule.cpp \
		$$PWD/iprangerule.cpp \
		$$PWD/iprule.cpp \
		$$PWD/misscache.cpp \
		$$PWD/regexprule.cpp \
		$$PWD/sanitychecker.cpp \
		$$PWD/securerule.cpp \
		$$PWD/securitymanager.cpp \
		$$PWD/useragentrule.cpp
