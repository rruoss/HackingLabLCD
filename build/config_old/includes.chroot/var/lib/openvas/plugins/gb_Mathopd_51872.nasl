###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Mathopd_51872.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mathopd Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Mathopd is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Versions prior to Mathopd 1.5p7 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103427);
 script_bugtraq_id(51872);
 script_cve_id("CVE-2012-1050");
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_name("Mathopd Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51872");
 script_xref(name : "URL" , value : "http://www.mathopd.org/");
 script_xref(name : "URL" , value : "http://www.mail-archive.com/mathopd%40mathopd.org/msg00392.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521507");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-16 15:14:41 +0100 (Thu, 16 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed Mathopd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("host_details.inc"); 
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server: Mathopd/" >!< banner)exit(0);

version = eregmatch(pattern:"Server: Mathopd/([0-9.p]+)",string:banner);
vers = version[1];

if(!isnull(vers) && vers >!< "unknown") {

  if("p" >< vers) {
    vers1 = split(vers,sep:"p",keep:FALSE);
    if(!isnull(vers1[1])) {
      vers = vers1[0] + '.p' + vers1[1];
    }  
  }  

  if(version_is_less(version: vers, test_version: "1.5.p7")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

