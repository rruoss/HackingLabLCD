# OpenVAS Vulnerability Test
# $Id: tftp_files_cisco_ios_ca.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TFTP file detection (Cisco IOS CA)
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
tag_solution = "If it is not required, disable the TFTP server. Otherwise restrict access to
trusted sources only.";

tag_summary = "The remote host has a TFTP server installed that is serving one or more 
sensitive Cisco IOS Certificate Authority (CA) files.";

tag_insight= "These files potentially include the private key for the CA so should be considered 
extremely sensitive and should not be exposed to unnecessary scrutiny.";

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
	script_id(17341);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
	name="TFTP file detection (Cisco IOS CA)";
	script_name(name);
        desc = "
        Summary:
        " + tag_summary + "
        Vulnerability Insight:
        " + tag_insight + "
        Solution:
        " + tag_solution;
        script_description(desc);
	summary="Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS CA)";
	script_summary(summary);
	script_category(ACT_ATTACK);
	script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
	family="General";
	script_family(family);
	script_dependencies("tftpd_detect.nasl");
	script_require_keys("Services/udp/tftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
 }
 	exit(0);
}



############## declarations ################







############## script ################

include("tftp.inc");

# initialise variables
local_var request_data;
local_var file_name;
local_var file_postfix;
local_var postfix_list;
local_var ca_name;
local_var detected_files;
local_var description;
postfix_list=make_list('.pub','.crl','.prv','.ser','#6101CA.cer','.p12');

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

# step through first nine certificate files
for(i=1;i<10;i++)
{
	# initialise variables
	file_name=raw_string(ord(i),'.cnm');
	
	# request numeric certificate file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		# initialise variables
		ca_name=eregmatch(string:request_data,pattern:'subjectname_str = cn=(.+),ou=');
		
		# check if cn is present in certificate file
		if(ca_name[1])
		{
			# add filename to response
			detected_files=raw_string(detected_files,file_name,"\n");
			
			# step through files
			foreach file_postfix (postfix_list)
			{
				# initialise variables
				file_name=raw_string(ca_name[1],file_postfix);

				# request certificate file
				if(request_data=tftp_get(port:port,path:file_name))
				{
					# add filename to response
					detected_files=raw_string(detected_files,file_name,"\n");
				}
			}
			
			break;
		}
	}
}

# check if any files were detected
if(detected_files)
{
	description= "
The remote host has a TFTP server installed that is serving one or 
more sensitive Cisco IOS Certificate Authority (CA) files.

The filenames detected are:

" +detected_files + "

These files potentially include the private key for the CA so should be 
considered extremely sensitive and should not be exposed to 
unnecessary scrutiny.

Solution: If it is not required, disable the TFTP server. Otherwise restrict 
access to trusted sources only.";
	security_warning(data:description,port:port,proto:"udp");
}


exit(0);
