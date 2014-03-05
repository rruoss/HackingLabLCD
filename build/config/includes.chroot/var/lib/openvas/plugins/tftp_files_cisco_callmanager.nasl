# OpenVAS Vulnerability Test
# $Id: tftp_files_cisco_callmanager.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TFTP file detection (Cisco CallManager)
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)
#
# Copyright:
# Copyright (C) 2005 Corsaire Limited
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
tag_solution = "If it is not required, disable or uninstall the TFTP server.
Otherwise restrict access to trusted sources only.";
tag_summary = "The remote host has a TFTP server installed that is serving one or more Cisco 
CallManager files.
These files do not themselves include any sensitive information, but do identify 
the TFTP server as being part of a Cisco CallManager environment. The CCM TFTP 
server is an essential part of providing VOIP handset functionality, so should 
not be exposed to unnecessary scrutiny.";

# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server

# declare description
if(description)
{
	script_id(19507);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
	name="TFTP file detection (Cisco CallManager)";
	script_name(name);
  desc = "
  Summary:
  " + tag_summary + "

 Solution:
 " + tag_solution;
        script_description(desc);
	summary="Determines if the remote host has sensitive files exposed via TFTP (Cisco CallManager)";
	script_summary(summary);
	script_category(ACT_ATTACK);
	script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
	family="General";
	script_family(family);
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/tftp");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 	exit(0);
}



############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);




############## script ################

include("tftp.inc");

file_list = make_list('/MOH/SampleAudioSource.xml','RingList.xml','Annunciator.xml');

# step through files
foreach file_name (file_list)
{
	if( tftp_get(port:port,path:file_name) )
	{
		security_hole(port:port,proto:"udp");
		exit(0);
	}
}


