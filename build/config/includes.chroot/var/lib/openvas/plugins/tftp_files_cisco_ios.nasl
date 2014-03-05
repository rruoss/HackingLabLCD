# OpenVAS Vulnerability Test
# $Id: tftp_files_cisco_ios.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TFTP file detection (Cisco IOS)
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
tag_solution = "If it is not required, disable the TFTP server. Otherwise
restrict access to trusted sources only.";

tag_summary = "The remote host has a TFTP server installed that is serving one or 
more sensitive Cisco IOS files.\n\nThese files potentially include 
passwords and other sensitive information, so should not be exposed 
to unnecessary scrutiny.";
# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.


############## description ################



# declare description
if(description)
{
	script_id(17342);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
	name="TFTP file detection (Cisco IOS)";
	script_name(name);
  desc = "
  Summary:
  " + tag_summary + "

 Solution:
 " + tag_solution;	script_description(desc);
	summary="Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS)";
	script_summary(summary);
	script_category(ACT_ATTACK);
	script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
	family="Remote file access";
	script_family(family);
	script_dependencies('tftpd_detect.nasl', 'tftpd_backdoor.nasl');
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor');	# Not wise
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 	exit(0);
}



############## declarations ################





############## script ################

include("tftp.inc");
include("misc_func.inc");

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

# Avoid FP
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

# initialise variables
local_var request_data;
local_var detected_files;
local_var file_name;
local_var file_list;
file_list=make_list('startup-config','network-confg','network.cfg','network.confg','cisconet-confg','cisconet.cfg','cisconet.confg','router-confg','router.config','router.cfg','ciscortr-confg','ciscortr.config','ciscortr.cfg','cisco-confg','cisco.confg','cisco.cfg');

if ( tftp_get(port:port,path:rand_str(length:10)) ) exit(0); 


# step through files
foreach file_name (file_list)
{
	# request file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		# add filename to response
		detected_files=raw_string(detected_files,file_name,"\n");
	}
}


# check if any files were detected
if(detected_files)
{
	description= "
The remote host has a TFTP server installed that is serving 
one or more sensitive Cisco IOS files.

The filenames detected are :

" + detected_files + "

These files potentially include passwords and other sensitive information, 
so should not be exposed to unnecessary scrutiny.

Solution: If it is not required, disable the TFTP server. Otherwise restrict 
access to trusted sources only.";
	security_warning(data:description,port:port,proto:"udp");
}

exit(0);
