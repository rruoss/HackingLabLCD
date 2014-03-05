# OpenVAS
# $Id: lsc_options.nasl 14 2013-10-27 12:33:37Z jan $
# Description: This script allows to set some Options for LSC.
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

include("revisions-lib.inc");
tag_summary = "This script allows users to set some Options for Local Security
Checks.

These data are stored in the knowledge base
and used by other tests.";

if(description)
{
 script_id(100509);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Options for Local Security Checks");

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Sets some Options for Local Security Checks.");
 script_category(ACT_SETTINGS);
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_family("Settings");

 # Use find command yes/no
 script_add_preference(name:"Also use 'find' command to search for Applications", type:"checkbox", value:"yes");
 # add -xdev to find yes/no
 script_add_preference(name:"Descend directories on other filesystem (don't add -xdev to find)", type:"checkbox", value:"yes");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

find_enabled       = script_get_preference("Also use 'find' command to search for Applications");
nfs_search_enabled = script_get_preference("Descend directories on other filesystem (don't add -xdev to find)");

if (find_enabled) { 
  set_kb_item(name: "Enable/find", value: find_enabled);
}

if (nfs_search_enabled) {
  set_kb_item(name: "Descend/OFS", value: nfs_search_enabled);
}

exit(0);
