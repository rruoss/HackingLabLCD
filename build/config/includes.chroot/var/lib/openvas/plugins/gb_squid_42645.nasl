###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_42645.nasl 14 2013-10-27 12:33:37Z jan $
#
# Squid 'DNS' Reply Remote Buffer Overflow Vulnerability
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
tag_summary = "Squid is prone to a remote buffer-overflow vulnerability because it
fails to perform adequate boundary checks on user-supplied data.

An attacker can exploit this issue to execute arbitrary code within
the context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

Squid 3.1.6 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100774);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2951");
 script_bugtraq_id(42645);

 script_name("Squid 'DNS' Reply Remote Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Squid version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_squid_detect.nasl");
 script_require_ports("Services/www", 3128, 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42645");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=62692");
 script_xref(name : "URL" , value : "http://marc.info/?l=squid-users&amp;m=128263555724981&amp;w=2");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_kb_item("Services/http_proxy");

if(!port){
    exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/Squid")))exit(0);

if(!isnull(vers)) {

  if(version_is_equal(version:vers, test_version:"3.1.6")) {

      security_warning(port:port);
      exit(0);

  }

}

exit(0);

