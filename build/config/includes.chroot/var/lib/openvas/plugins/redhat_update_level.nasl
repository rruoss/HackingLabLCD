# OpenVAS Vulnerability Test
# $Id: redhat_update_level.nasl 15791 2013-03-19 14:01:24Z mime $
# Description: RedHat update level
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
 script_tag(name:"deprecated", value:TRUE); 
 script_id(14657);
 script_version("$Revision: 15791 $");
 script_tag(name:"last_modification", value:"$Date: 2013-03-19 15:01:24 +0100 (Tue, 19 Mar 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "RedHat update level";
 
 script_name(name);
 
 desc = "This NVT is entirely outdated but also
in conflict with our current approach how to check
verndor security updates.";

 script_description(desc);
 
 summary = "Check for RedHat update level"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Red Hat Local Security Checks";
 script_family(family);
 
 script_dependencies("gather-package-list.nasl");
 script_require_keys("Host/RedHat/release");
 exit(0);
}

exit(66);
#the code

#here the list of redhat version/last update level

lastupdate[2]=7;
lastupdate[3]=6;
lastupdate[4]=1;

buf=get_kb_item("Host/RedHat/release");
if (!buf) exit(0);
v = eregmatch(string: buf, pattern: "Update ([0-9]+)");
if (isnull(v)) exit(0);
updatelevel=int(v[1]);

release=NULL;
if(egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:buf) ) release=3;
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:buf) ) release=2; 
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 4", string:buf) ) release=4;

if (isnull(release)) exit(0);

if (updatelevel < lastupdate[release])
{
str="The remote host is missing a RedHat update package.
Maintenance level "+updatelevel+" is installed, last is "+lastupdate[release]+".

You should install this package for your system to be up-to-date.

Solution : http://www.redhat.com/security/notes/ ";
 security_warning(port:port, data:str);
 exit(0);
}
