'''
gtkOutput.py

Copyright 2008 Andres Riancho

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

# Only to be used with care.
import Queue
import os

# I'm timestamping the messages
import time

from core.controllers.basePlugin.baseOutputPlugin import baseOutputPlugin
from core.controllers.w3afException import w3afException
from core.controllers.misc.homeDir import get_home_dir
from core.data.db.history import HistoryItem
from core.data.db.db import DB
# The output plugin must know the session name that is saved in the config object,
# the session name is assigned in the target settings
import core.data.kb.config as cf
import core.controllers.outputManager as om
import core.data.kb.knowledgeBase as kb
import core.data.constants.severity as severity
# options
from core.data.options.option import option
from core.data.options.optionList import optionList

class gtkOutput(baseOutputPlugin):
    '''
    Saves messages to kb.kb.getData('gtkOutput', 'queue'), messages are saved in the form of objects.
    
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''
    
    def __init__(self):
        baseOutputPlugin.__init__(self)
        
        if not kb.kb.getData('gtkOutput', 'db') == []:
            # Restore it from the kb
            self._db = kb.kb.getData('gtkOutput', 'db')
            self.queue = kb.kb.getData('gtkOutput', 'queue')
        else:
            self.queue = Queue.Queue()
            kb.kb.save('gtkOutput', 'queue' , self.queue)
            # Create DB and add tables
            sessionName = cf.cf.getData('sessionName')
            dbName = os.path.join(get_home_dir(), 'sessions', 'db_' + sessionName)
            # Just in case the directory doesn't exist...
            try:
                os.mkdir(os.path.join(get_home_dir() , 'sessions'))
            except OSError, oe:
                # [Errno 17] File exists
                if oe.errno != 17:
                    msg = 'Unable to write to the user home directory: ' + get_home_dir()
                    raise w3afException( msg )

            self._db = DB()
            # Check if the database already exists
            if os.path.exists(dbName):
                # Find one that doesn't exist
                for i in xrange(100):
                    newDbName = dbName + '-' + str(i)
                    if not os.path.exists(newDbName):
                        dbName = newDbName
                        break

            # Create DB!
            self._db.open(dbName)
            # Create table
            historyItem = HistoryItem(self._db)
            self._db.createTable(historyItem.getTableName(),
                    historyItem.getColumns(),
                    historyItem.getPrimaryKeyColumns())
            kb.kb.save('gtkOutput', 'db', self._db)
    
    def debug(self, msgString, newLine = True ):
        '''
        This method is called from the output object. The output object was called from a plugin
        or from the framework. This method should take an action for debug messages.
        '''
        m = message( 'debug', self._cleanString(msgString), time.time(), newLine )
        self._addToQueue( m )
    
    def information(self, msgString , newLine = True ):
        '''
        This method is called from the output object. The output object was called from a plugin
        or from the framework. This method should take an action for informational messages.
        ''' 
        m = message( 'information', self._cleanString(msgString), time.time(), newLine )
        self._addToQueue( m )

    def error(self, msgString , newLine = True ):
        '''
        This method is called from the output object. The output object was called from a plugin
        or from the framework. This method should take an action for error messages.
        '''     
        m = message( 'error', self._cleanString(msgString), time.time(), newLine )
        self._addToQueue( m )

    def vulnerability(self, msgString , newLine=True, severity=severity.MEDIUM ):
        '''
        This method is called from the output object. The output object was called from a plugin
        or from the framework. This method should take an action when a vulnerability is found.
        '''     
        m = message( 'vulnerability', self._cleanString(msgString), time.time(), newLine )
        m.setSeverity( severity )
        self._addToQueue( m )
        
    def console( self, msgString, newLine = True ):
        '''
        This method is used by the w3af console to print messages to the outside.
        '''
        m = message( 'console', self._cleanString(msgString), time.time(), newLine )
        self._addToQueue( m )
    
    def _addToQueue( self, m ):
        '''
        Adds a message object to the queue. If the queue isn't there, it creates one.
        '''
        self.queue.put( m )
    
    def logHttp( self, request, response):
        historyItem = HistoryItem()
        try:
            historyItem.request = request
            historyItem.response = response
            historyItem.save()
        except KeyboardInterrupt, k:
            raise k
        except Exception, e:
            msg = 'Exception while inserting request/response to the database: ' + str(e) + '\n'
            msg += 'The request/response that generated the error is: '+ str(response.getId())
            msg += ' ' + request.getURI() + ' ' + response.getCode()
            om.out.error( msg )
            raise e
    
    def logEnabledPlugins(self,  enabledPluginsDict,  pluginOptionsDict):
        '''
        This method is called from the output managerobject. 
        This method should take an action for the enabled plugins 
        and their configuration.
        '''
        pass
        
    def getLongDesc( self ):
        '''
        @return: A DETAILED description of the plugin functions and features.
        '''
        return '''
        Saves messages to kb.kb.getData('gtkOutput', 'queue'), messages are saved in the form of
         objects. This plugin was created to be able to communicate with the gtkUi and should be
         enabled if you are using it.
        '''
        
    def getOptions( self ):
        '''
        @return: A list of option objects for this plugin.
        '''    
        ol = optionList()
        return ol
    
    def setOptions( self, OptionList ):
        pass
        
class message:
    def __init__( self, msg_type, msg , msg_time, newLine=True ):
        '''
        @parameter msg_type: console, information, vulnerability, etc
        @parameter msg: The message itself
        @parameter msg_time: The time when the message was produced
        @parameter newLine: Should I print a newline ? True/False
        '''
        self._type = msg_type
        self._msg = msg
        self._newLine = newLine
        self._time = msg_time
        self._severity = None
    
    def getSeverity( self ):
        return self._severity
        
    def setSeverity( self, the_severity ):
        self._severity = the_severity
    
    def getMsg( self ):
        return self._msg
    
    def getType( self ):
        return self._type
        
    def getNewLine( self ):
        return self._newLine
        
    def getRealTime( self ):
        return self._time

    def getTime( self ):
        return time.strftime("%c", time.localtime(self._time))
