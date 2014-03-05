###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsftpd_46617.nasl 13 2013-10-27 12:16:33Z jan $
#
# vsftpd FTP Server 'ls.c' Remote Denial of Service Vulnerability
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
tag_summary = "The 'vsftpd' FTP server is prone to a remote denial-of-service
vulnerability.

Successfully exploiting this issue allows remote attackers to crash
the affected application, denying service to legitimate users.";

tag_solution = "Fixes are available. Please see the references for more information.";

if (description)
{
 script_id(103101);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
 script_bugtraq_id(46617);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0762");

 script_name("vsftpd FTP Server 'ls.c' Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46617");
 script_xref(name : "URL" , value : "ftp://vsftpd.beasts.org/users/cevans/untar/vsftpd-2.3.4/Changelog");
 script_xref(name : "URL" , value : "http://vsftpd.beasts.org/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed vsftpd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("ftp_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

if(!banner = get_ftp_banner(port)) exit(0);
if("vsftpd" >!< tolower(banner))exit(0);
version = eregmatch(pattern:"vsftpd ([0-9.]+)", string:   tolower(banner));
if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(vers)) {

    if(version_in_range(version:vers, test_version:"2.3", test_version2:"2.3.2") ) {
        security_warning(port: port);
        exit(0);

    }
}

exit(0);

