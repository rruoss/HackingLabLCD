# OpenVAS Vulnerability Test
# $Id: pwsphp_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PWSPHP XSS
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
tag_summary = "The remote host runs PWSPHP (Portail Web System) a CMS written in PHP.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on the 'skin' parameter
in the script SettingsBase.php.

With a specially crafted URL, an attacker could use the remote server
to set up a cross site script attack.";

tag_solution = "Upgrade to version 1.2.3 or newer";

# Ref: SecuBox fRoGGz <unsecure@writeme.com>

if(description)
{
  script_id(18216);
  script_version("$Revision: 17 $");
  script_bugtraq_id(13561, 13563);
  script_cve_id("CVE-2005-1508");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PWSPHP XSS");

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  script_summary("Checks XSS in PWSPHP");
  script_category(ACT_GATHER_INFO);
  
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_port_state(port))
{
   foreach d ( cgi_dirs() )
   {
    buf = http_get(item:string(d,"profil.php?id=1%20<script>foo</script>"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);
    if("title>PwsPHP " >< r && (egrep(pattern:"<script>foo</script>", string:r)))
    {
      security_hole(port);
      exit(0);
    }
   }
}
