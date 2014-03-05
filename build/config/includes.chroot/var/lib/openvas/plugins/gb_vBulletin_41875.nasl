###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vBulletin_41875.nasl 14 2013-10-27 12:33:37Z jan $
#
# vBulletin 'faq.php' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
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
tag_summary = "vBulletin is prone to an information-disclosure vulnerability.

Successful exploits can allow attackers to obtain potentially
sensitive information which may aid in other attacks.

vBulletin 3.8.6 is affected; prior versions may also be vulnerable.";

tag_solution = "The vendor has released a patch to address this issue. Please see the
references for more information.";

if (description)
{
 script_id(100723);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-23 13:21:58 +0200 (Fri, 23 Jul 2010)");
 script_bugtraq_id(41875);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("vBulletin 'faq.php' Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41875");
 script_xref(name : "URL" , value : "http://www.vbulletin.com/forum/showthread.php?357818-Security-Patch-Release-3.8.6-PL1");
 script_xref(name : "URL" , value : "http://www.vbulletin.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512575");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if vBulletin is prone to an information-disclosure vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("vBulletin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"vBulletin")){
   exit(0);
}

url = string(dir,"/faq.php?s=&do=search&q=database&match=all&titlesonly=0"); 

if(buf = http_vuln_check(port:port, url:url,pattern:"Database")) {
  if("Name:" >< buf && "Host:" >< buf && "Port:" >< buf && "Username:" >< buf && "Password:" >< buf) {
    security_warning(port:port);
    exit(0);
  }  
}


exit(0);

