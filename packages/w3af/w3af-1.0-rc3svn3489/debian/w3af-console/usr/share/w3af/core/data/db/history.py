'''
Copyright 2009 Andres Riancho

This file is part of w3af, w3af.sourceforge.net .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

'''
from __future__ import with_statement
import thread
import sys
import re
import os

try:
    from cPickle import Pickler, Unpickler
except ImportError:
    from pickle import Pickler, Unpickler

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import core.data.kb.knowledgeBase as kb
import core.controllers.outputManager as om
import core.data.kb.config as cf
from core.controllers.w3afException import w3afException
from core.controllers.misc.homeDir import get_home_dir
from core.data.db.db import DB, WhereHelper


class HistoryItem:
    '''Represents history item.'''

    _db = None
    _dataTable = 'data_table'
    _columns = [('id','integer'), ('url', 'text'), ('code', 'text'), ('tag', 'text'),
            ('mark', 'integer'), ('info', 'text'), ('raw_pickled_data', 'blob')]
    _primaryKeyColumns = ['id',]
    id = None
    request = None
    response = None
    info = None
    mark = False
    tag = ''

    def __init__(self, db=None):
        '''Construct object.'''
        if db:
            self._db = db
        elif not kb.kb.getData('gtkOutput', 'db') == []:
            # Restore it from the kb
            self._db = kb.kb.getData('gtkOutput', 'db')
        else:
            raise w3afException('The database is not initialized yet.')

    def find(self, searchData, resultLimit=-1, orderData=[]):
        '''Make complex search.
        search_data = {name: (value, operator), ...}
        orderData = [(name, direction)]
        '''
        if not self._db:
            raise w3afException('The database is not initialized yet.')
        result = []
        sql = 'SELECT * FROM ' + self._dataTable
        where = WhereHelper(searchData)
        sql += where.sql()
        orderby = ""
        # 
        # TODO we need to move SQL code to parent class
        #
        for item in orderData:
            orderby += item[0] + " " + item[1] + ","
        orderby = orderby[:-1]

        if orderby:
            sql += " ORDER BY " + orderby

        sql += ' LIMIT '  + str(resultLimit)
        try:
            rawResult = self._db.retrieveAll(sql, where.values())
            for row in rawResult:
                item = self.__class__(self._db)
                item._loadFromRow(row)
                result.append(item)
        except w3afException:
            raise w3afException('You performed an invalid search. Please verify your syntax.')
        return result

    def _loadFromRow(self, row):
        '''Load data from row with all columns.'''
        f = StringIO(str(row[-1]))
        req, res = Unpickler(f).load()
        self.id = res.getId()
        self.request = req
        self.response = res
        self.info = row[-2]
        self.mark = bool(row[-3])
        self.tag = row[-4]

    def load(self, id=None):
        '''Load data from DB by ID.'''
        if not self._db:
            raise w3afException('The database is not initialized yet.')

        if not id:
            id = self.id

        sql = 'SELECT * FROM ' + self._dataTable + ' WHERE id = ? '
        try:
            row = self._db.retrieve(sql, (id,))
            self._loadFromRow(row)
        except w3afException:
            raise w3afException('You performed an invalid search. Please verify your syntax.')
        except Exception, e:
            msg = 'An internal error ocurred while searching for id "' + str(id) + '".'
            msg += ' Original exception: "' + str(e) + '".'
            raise w3afException( msg )
            
        return True

    def read(self, id):
        '''Return item by ID.'''
        if not self._db:
            raise w3afException('The database is not initialized yet.')
        resultItem = self.__class__(self._db)
        resultItem.load(id)
        return resultItem

    def save(self):
        '''Save object into DB.'''
        values = []
        values.append(self.response.getId())
        values.append(self.request.getURI())
        values.append(self.response.getCode())
        values.append(self.tag)
        values.append(int(self.mark))
        values.append(self.info)
        f = StringIO()
        p = Pickler(f)
        p.dump((self.request, self.response))
        values.append(f.getvalue())
        if not self.id:
            sql = 'INSERT INTO ' + self._dataTable + ' (id, url, code, tag, mark, info, raw_pickled_data)'
            sql += ' VALUES (?,?,?,?,?,?,?)'
            self._db.execute(sql, values)
            self.id = self.response.getId()
        else:
            values.append(self.id)
            sql = 'UPDATE ' + self._dataTable
            sql += ' SET id = ?, url = ?, code = ?, tag = ?, mark = ?, info = ?, raw_pickled_data = ? '
            sql += ' WHERE id = ?'
            self._db.execute(sql, values)
        return True

    def getColumns(self):
        return self._columns

    def getTableName(self):
        return self._dataTable

    def getPrimaryKeyColumns(self):
        return self._primaryKeyColumns

    def _updateField(self, name, value):
        '''Update custom field in DB.'''
        sql = 'UPDATE ' + self._dataTable
        sql += ' SET ' + name + ' = ? '
        sql += ' WHERE id = ?'
        self._db.execute(sql, (value, self.id))

    def updateTag(self, value, forceDb=False):
        '''Update tag.'''
        self.tag = value
        if forceDb:
            self._updateField('tag', value)

    def toggleMark(self, forceDb=False):
        '''Toggle mark state.'''
        self.mark = not self.mark
        if forceDb:
            self._updateField('mark', int(self.mark))
