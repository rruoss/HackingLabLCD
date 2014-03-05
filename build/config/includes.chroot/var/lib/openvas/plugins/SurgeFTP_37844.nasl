###############################################################################
# OpenVAS Vulnerability Test
# $Id: SurgeFTP_37844.nasl 14 2013-10-27 12:33:37Z jan $
#
# SurgeFTP 'surgeftpmgr.cgi' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Updated By: Antu Sanadi <santu@secpod.com> on 24-03-210
# included the 'CVE-2010-1068'
#
#Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "SurgeFTP is prone to multiple cross-site scripting vulnerabilities
because the application fails to sufficiently sanitize user-
supplied data.

Attacker-supplied HTML or JavaScript code could run in an
administrator's browser session in the context of the affected site.
This could potentially allow the attacker to steal cookie-based
authentication credentials; other attacks are also possible.

SurgeFTP 2.3a6 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100453);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
 script_cve_id("CVE-2010-1068");
 script_bugtraq_id(37844);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("SurgeFTP 'surgeftpmgr.cgi' Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if SurgeFTP version is <= 2.3a6");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37844");
 script_xref(name : "URL" , value : "http://netwinsite.com/surgeftp/");
 exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

if(!banner = get_ftp_banner(port))exit(0);
if("SurgeFTP" >!< banner)exit(0);

version = eregmatch(pattern:"SurgeFTP.*\(Version ([^)]+)\)", string: banner);
if(isnull(version[1]))exit(0);

vers = version[1];

if(!isnull(vers)) {

    if(version_is_less_equal(version:vers, test_version:"2.3a6") ) {
        security_warning(port: port);
        exit(0);

    }
}

exit(0);
