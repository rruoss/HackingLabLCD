###############################################################################
# OpenVAS Vulnerability Test
# $Id: ruby_WEBrick_37710.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ruby WEBrick Terminal Escape Sequence in Logs Command Injection Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "Ruby WEBrick is prone to a command-injection vulnerability because it
fails to adequately sanitize user-supplied input in log files.

Attackers can exploit this issue to execute arbitrary commands in
a terminal.

Versions *prior to* the following are affected:

Ruby 1.8.6 patchlevel 388 Ruby 1.8.7 patchlevel 249 Ruby 1.9.1
patchlevel 378";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100445);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
 script_bugtraq_id(37710);
 script_cve_id("CVE-2009-4492");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Ruby WEBrick Terminal Escape Sequence in Logs Command Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37710");
 script_xref(name : "URL" , value : "http://www.ruby-lang.org");
 script_xref(name : "URL" , value : "http://www.ruby-lang.org/en/news/2010/01/10/webrick-escape-sequence-injection/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508830");

 script_description(desc);
 script_summary("Determine the Ruby version");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Server: WEBrick" >!< banner)exit(0);
if(!matches = eregmatch(pattern: "Server: WEBrick/[0-9.]+ \(Ruby/([0-9.]+)/([0-9]{4}-[0-9]{2}-[0-9]{2})\)", string: banner))exit(0);
if(isnull(matches[1]) || isnull(matches[2]))exit(0);

release = matches[1];
release_date = matches[2];

  if(version_is_equal(version: release, test_version: "1.8.6") || 
     version_is_equal(version: release, test_version: "1.8.7") ||
     version_is_equal(version: release, test_version: "1.9.1")) {
      
      rdate = split(release_date, sep: "-", keep: FALSE);
      if(isnull(rdate[0]) || isnull(rdate[1]) || isnull(rdate[2]))exit(0);

      if(int(rdate[0]) < 2010) {
        VULN = TRUE;
      }
      else if(int(rdate[0]) == 2010 && int(rdate[1]) == 1 && int(rdate[2]) < 10) {
        VULN = TRUE;
      }	
      
      if(VULN) {
        security_warning(port:port);
        exit(0);
      }	
  }


exit(0);

