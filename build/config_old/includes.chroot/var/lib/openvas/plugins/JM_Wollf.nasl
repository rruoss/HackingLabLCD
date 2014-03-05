# OpenVAS Vulnerability Test
# $Id: JM_Wollf.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Wollf backdoor detection
#
# Authors:
# Jøséph Mlødzianøwski <joseph@rapter.net>
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
# Updated the CVSS Base and Risk Factor
#
# Copyright:
# Copyright (C) 2003 J.Mlødzianøwski
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

include("revisions-lib.inc");
tag_summary = "This host appears to be running Wollf on this port. Wollf Can be used as a 
Backdoor which allows an intruder gain remote access to files on your computer. 
If you did not install this program for remote management then this host may 
be compromised.

An attacker may use it to steal your passwords, or redirect
ports on your system to launch other attacks";

tag_solution = "see www.rapter.net/jm4.htm for details on removal";

if(description)
{

 script_id(11881);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical"); 
 name = "Wollf backdoor detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Determines the presence of Wollf";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2003 J.Mlødzianøwski");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


#
# The code starts here:
#

port = get_kb_item("Services/wollf");
if ( port ) security_hole(port);

