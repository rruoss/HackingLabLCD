###############################################################################
# OpenVAS Vulnerability Test
# $Id: pdns_jan_10.nasl 14 2013-10-27 12:33:37Z jan $
#
# PowerDNS multiple vulnerabilities January 2010
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
tag_summary = "PowerDNS is prone to a remote cache-poisoning vulnerability and to a
Buffer Overflow Vulnerability.

An attacker can exploit the remote cache-poisoning vulnerability to
divert data from a legitimate site to an attacker-specified site.
Successful exploits will allow the attacker to manipulate cache data,
potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
service attacks.

Successfully exploiting of the Buffer Overflow vulnerability allows a
remote attacker to execute arbitrary code with superuser privileges,
resulting in a complete compromise of the affected computer. Failed
exploits will cause a denial of service. 

PowerDNS 3.1.7.1 and earlier are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100433);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)");
 script_bugtraq_id(37653,37650);
 script_cve_id("CVE-2009-4010","CVE-2009-4009");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("PowerDNS multiple vulnerabilities January 2010");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37653");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37650");
 script_xref(name : "URL" , value : "http://www.powerdns.com/");
 script_xref(name : "URL" , value : "http://doc.powerdns.com/powerdns-advisory-2010-02.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508743");

 script_description(desc);
 script_summary("Determine if PowerDNS version is < 3.1.7.2 ");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("pdns_version.nasl");
 script_require_keys("powerdns/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

udpPort = 53;
if(!get_udp_port_state(udpPort)){
  exit(0);
}

bindVer = get_kb_item("powerdns/version");
if(!bindVer){
  exit(0);
}

if("Recursor" >!< bindVer)exit(0);
version = eregmatch(pattern:"([0-9.]+)", string: bindVer);
if(isnull(version[1]))exit(0);

if(version_is_less(version:version[1], test_version:"3.1.7.2") ) {
  security_hole(port:udpPort, proto:"udp");
  exit(0);
}

exit(0);
