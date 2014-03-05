# -*- coding: iso-8859-1 -*-

"""Logger singleton.

This module allows halberd to easily log certain events.
"""

# Copyright (C) 2004, 2005, 2006 Juan M. Bello Rivas <jmbr@superadditive.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import sys
import logging


_logger = None

#_logfmt = '%(name)s %(thread)d %(asctime)s %(levelname)s %(message)s'
_logfmt = '%(levelname)s %(message)s'


def getLogger():
    """Get a reference to an instance of a logger object.

    @return: reference to a logger.
    @rtype: C{object}
    """
    global _logger

    if _logger is None:
        _logger = logging.getLogger('Halberd')
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_logfmt))
        _logger.addHandler(handler)
        _logger.setLevel(logging.INFO)

    return _logger

def setDebug():
    """Set the logging level to C{debug}.
    """
    logger = getLogger()
    logger.setLevel(logging.DEBUG)

def setError():
    """Set the logging level to C{error}.
    """
    logger = getLogger()
    logger.setLevel(logging.ERROR)


# vim: ts=4 sw=4 et
