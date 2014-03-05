# OpenVAS Vulnerability Test
# $Id: tftp_files_hp_ignite_ux_passwd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TFTP file detection (HP Ignite-UX passwd)
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
tag_solution = "Upgrade to a version of the Ignite-UX application that does not exhibit this
behaviour. If it is not required, disable or uninstall the TFTP server. 
Otherwise restrict access to trusted sources only.";

tag_summary = "The remote host has a vulnerable version of the HP Ignite-UX application installed 
that exposes the /etc/passwd file to anonymous TFTP access.";

# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server

# declare description
if(description)
{
	script_id(19509);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
	script_bugtraq_id(14568);
	script_cve_id("CVE-2004-0951");

    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
	name="TFTP file detection (HP Ignite-UX passwd)";
	script_name(name);
        desc = "
        Summary:
        " + tag_summary + "
        Solution:
        " + tag_solution;
	script_description(desc);
	summary="Determines if the remote host has sensitive files exposed via TFTP (HP Ignite-UX passwd)";
	script_summary(summary);
	script_category(ACT_ATTACK);
	script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
	family="General";
	script_family(family);
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/tftp");
	
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 script_xref(name : "URL" , value : "http://www.corsaire.com/advisories/c041123-001.txt");
 	exit(0);
}



############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);






############## script ################

include("tftp.inc");


# initialise test
file_name='/var/opt/ignite/recovery/passwd.makrec';
if(tftp_get(port:port,path:file_name)) security_hole(port:port,proto:"udp");
