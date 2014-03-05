# OpenVAS Vulnerability Test
# $Id: jaws_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: JAWS HTML injection vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav
# Fixed by Tenable:
#   - added CVE xrefs.
#   - added details about the problem to the description.
#   - added See also and Solution.
#   - fixed script family.
#   - fixed exploit and extended it to cover versions 0.4.x.
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
tag_summary = "The remote host is running JAWS, a content management system written in PHP.

The remote version of this software does not perform a proper
validation of user-supplied input to several variables used in the
'GlossaryModel.php' script, and is therefore vulnerable to cross-site
scripting attacks.";

tag_solution = "Upgrade to JAWS 0.5.2 or later.";

if(description)
{
 script_id(19394);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-1231", "CVE-2005-1800");
 script_bugtraq_id(13254, 13796);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "JAWS HTML injection vulnerabilities";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks for HTML injection vulnerabilities in JAWS";

 script_summary(summary);

 script_category(ACT_ATTACK);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://seclists.org/lists/fulldisclosure/2005/Apr/0416.html");
 script_xref(name : "URL" , value : "http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034354.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);
if(!can_host_php(port:port)) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Exploits
exploits = make_list(
  # for 0.5.x
  string("gadget=Glossary&action=ViewTerm&term=", exss),
  # for 0.4.x
  string("gadget=Glossary&action=view&term=", exss)
);


foreach dir ( cgi_dirs() ) {
  foreach exploit (exploits) {
    req = http_get(item:string(dir, "/index.php?", exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (
      'Term does not exists' >< res && 
      xss >< res
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
