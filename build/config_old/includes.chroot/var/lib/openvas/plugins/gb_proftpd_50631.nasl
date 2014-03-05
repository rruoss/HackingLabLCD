###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_50631.nasl 13 2013-10-27 12:16:33Z jan $
#
# ProFTPD Prior To 1.3.3g Use-After-Free Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "ProFTPD is prone to a remote code-execution vulnerability.

Successful exploits will allow attackers to execute arbitrary code
within the context of the application. Failed exploit attempts will
result in a denial-of-service condition.

ProFTPD prior to 1.3.3g are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103331);
 script_bugtraq_id(50631);
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_version("$Revision: 13 $");
 script_cve_id("CVE-2011-4130");

 script_name("ProFTPD Prior To 1.3.3g Use-After-Free Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50631");
 script_xref(name : "URL" , value : "http://bugs.proftpd.org/show_bug.cgi?id=3711");
 script_xref(name : "URL" , value : "http://www.proftpd.org");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-328/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-15 10:15:56 +0100 (Tue, 15 Nov 2011)");
 script_description(desc);
 script_summary("Determine if ProFTPD version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_proftpd_server_remote_detect.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP.

## Get FTP Port
port = get_kb_item("Services/ftp");
if(!port){
    port = 21;
}

if(!get_port_state(port)){
    exit(0);
}

## Get Version from KB
version = get_kb_item("ProFTPD/Ver");
if(!isnull(version))
{
    ## Check for ProFTPD versions prior to 1.3.2rc3
    if(version_is_less(version:version,  test_version:"1.3.3g")){
          security_hole(port);
	  exit(0);
    }
}

exit(0);
