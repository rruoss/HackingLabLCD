'''
form.py

Copyright 2006 Andres Riancho

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

from core.data.dc.dataContainer import dataContainer
import copy
from core.data.parsers.encode_decode import urlencode


class form(dataContainer):
    '''
    This class represents a HTML form.
    
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''
    def __init__(self, init_val=(), strict=False):
        dataContainer.__init__(self)
        
        # Internal variables
        self._method = None
        self._action = None
        self._types = {}
        self._files = []
        self._selects = {}
        self._submitMap = {}
        
        # it is used for processing checkboxes
        self._secret_value = "3_!21#47w@"
        
    def getAction(self):
        '''
        @return: The form action.
        '''
        return self._action
        
    def setAction(self, action):
        self._action = action
        
    def getMethod(self):
        '''
        @return: The form method.
        '''
        return self._method
    
    def setMethod(self, method):
        self._method = method.upper()
    
    def getFileVariables( self ):
        return self._files

    def _setVar(self, name, value):
        '''
        Auxiliary setter for name=value
        '''
        # added to support repeated parameter names
        if name in self:
            self[name].append(value)
        else:
            self[name] = [value, ]

    def addFileInput( self, attrs ):
        '''
        Adds a file input to the form
        @parameter attrs: attrs=[("class", "screen")]
        '''
        name = ''

        for attr in attrs:
            if attr[0] == 'name':
                name = attr[1]
                break

        if not name:
            for attr in attrs:
                if attr[0] == 'id':
                    name = attr[1]
                    break

        if name:
            self._files.append( name )
            self._setVar(name, '')
            # TODO: This does not work if there are different parameters in a form
            # with the same name, and different types
            self._types[name] = 'file'

    def __str__( self ):
        '''
        This method returns a string representation of the form Object.
        @return: string representation of the form Object.
        '''
        tmp = self.copy()
        for i in self._submitMap:
            tmp[i] = self._submitMap[i]
        
        #
        #   FIXME: hmmm I think that we are missing something here... what about self._select values. See FIXME below.
        #   Maybe we need another for?
        #

        return urlencode( tmp )
    
    def copy(self):
        '''
        This method returns a copy of the form Object.
        
        @return: A copy of myself.
        '''
        return copy.deepcopy( self )
        
    def addSubmit( self, name, value ):
        '''
        This is something I hadn't thought about !
        <input type="submit" name="b0f" value="Submit Request">
        '''
        self._submitMap[name] = value
        
    def addInput(self, attrs):
        '''
        Adds a input to the form
        
        @parameter attrs: attrs=[("class", "screen")]
        '''

        '''
        <INPUT type="text" name="email"><BR>
        <INPUT type="radio" name="sex" value="Male"> Male<BR>
        '''
        # Set the default input type to text.
        attr_type = 'text'
        name = value = ''
        
        # Try to get the name:
        for attr in attrs:
            if attr[0] == 'name':
                name = attr[1]
        if not name:
            for attr in attrs:
                if attr[0] == 'id':
                    name = attr[1]

        if not name:
            return (name, value)

        # Find the attr_type
        for attr in attrs:
            if attr[0] == 'type':
                attr_type = attr[1].lower()

        # Find the default value
        for attr in attrs:
            if attr[0] == 'value':
                value = attr[1]

        if attr_type == 'submit':
            self.addSubmit( name, value )
        else:
            self._setVar(name, value)
        
        # Save the attr_type
        self._types[name] = attr_type
        
        #
        # TODO May be create special internal method instead of using
        # addInput()?
        #
        return (name, value)

    def getType( self, name ):
        return self._types[name]

    def addCheckBox(self, attrs):
        """
        Adds radio field
        """
        name, value = self.addInput(attrs)

        if not name:
            return

        if name not in self._selects:
            self._selects[name] = []

        if value not in self._selects[name]:
            self._selects[name].append(value)
            self._selects[name].append(self._secret_value)
            
        self._types[name] = 'checkbox'

    def addRadio(self, attrs):
        """
        Adds radio field
        """
        name, value = self.addInput(attrs)

        if not name:
            return
        
        self._types[name] = 'radio'
        
        if name not in self._selects:
            self._selects[name] = []

        #
        #   FIXME: how do you maintain the same value in self._selects[name] and in self[name] ?
        #
        if value not in self._selects[name]:
            self._selects[name].append(value)

    def addSelect(self, name, options):
        """
        Adds one more select field with options
        Options is list of options attrs (tuples)
        """
        self._selects[name] = []
        self._types[name] = 'select'
        
        value = ""
        for option in options:
            for attr in option:
                if attr[0].lower() == "value":
                    value = attr[1]
                    self._selects[name].append(value)

        self._setVar(name, value)

    def getVariantsCount(self, mode="all"):
        """
        Return count of variants of current form
        P.S. Combinatorics rulez!
        """
        result = 1
        if mode in ["t", "b"]:
            return result
        for i in self._selects:
            tmp = len(self._selects[i])
            if "tb" == mode and tmp > 1:
                tmp = 2
            if "tmb" == mode and tmp > 2:
                tmp = 3
            result *= tmp
        return result

    def _needToAdd(self, mode, opt_index, opt_count):
        """
        Checks if option with opt_index is needed to be added
        """
        if opt_count <= 1 or mode == "all":
            return True
        if mode in ["t", "tb", "tmb"] and opt_index == 0:
            return True
        if mode in ["tb", "tmb", "b"] and opt_index == (opt_count - 1):
            return True
        if "tmb" == mode and opt_index == (opt_count / 2):
            return True
        return False

    def getVariants(self, mode="all"):
        """
        Returns all variants of form by mode:
          "all" - all values
          "tb" - only top and bottom values
          "tmb" - top, middle and bottom values
          "t" - top values
          "b" - bottom values
        """
        result = []
        variants = []

        for i in self._selects:
            tmp_result = copy.deepcopy(result)
            result = []
            opt_count = len(self._selects[i])
            opt_index = 0
            for j in self._selects[i]:
                if not self._needToAdd(mode, opt_index, opt_count):
                    opt_index += 1
                    continue
                if len(tmp_result) == 0:
                    tmp = []
                    tmp.append((i,j))
                    result.append(tmp)
                    opt_index += 1
                    continue
                for prev in tmp_result:
                    tmp = []
                    for prev_i in prev:
                        tmp.append(prev_i)
                    tmp.append((i,j))
                    result.append(tmp)
                opt_index += 1

        for variant in result:
            tmp = copy.deepcopy(self)
            for select_variant in variant:
                if select_variant[1] != self._secret_value:
                    # FIXME: Needs to support repeated parameter names
                    tmp[select_variant[0]] = [select_variant[1], ]
                else:
                    # FIXME: Is it good solution to simply delete unwant to
                    # send checkboxes? 
                    del(tmp[select_variant[0]])
            variants.append(tmp)

        variants.append(self)

        return variants
