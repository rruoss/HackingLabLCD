# OpenVAS Vulnerability Test
# $Id$
# Description: Functions related to test for presence of tools.
#
# Authors:
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#


#
# @todo See toolcheck.nasl for things to be done.
#

# Compatibility function for script_mandatory_keys in combination with kb
# items set by toolcheck.nasl .
#
# Does nothing if "script_mandatory_keys" is defined (true for more recent
# versions of openvas-scanner) or the tool in question found in the path.
# Otherwise (== older server and tool is not found)
# sends a log message and calls exit (5).
#
function exit_if_not_found (toolname)
{
  if (defined_func ("script_mandatory_keys"))
    return;

  if (!find_in_path (string(toolname)))
    {
      msg = "The tool '";
      msg += string(toolname);
      msg += "' was not found on the scanserver.
Thus, this NVT was NOT executed.
Also, you are advised to update your installation of OpenVAS.";
      log_message(port: 0, data: msg);
      exit (5);
    }

  return;
}
