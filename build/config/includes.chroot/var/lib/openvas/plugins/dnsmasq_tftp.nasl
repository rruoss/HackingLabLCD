###############################################################################
# OpenVAS Vulnerability Test
# $Id: dnsmasq_tftp.nasl 15 2013-10-27 12:49:54Z jan $
#
# Dnsmasq TFTP Service multiple vulnerabilities
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
tag_summary = "Dnsmasq is prone to a remotely exploitable heap-overflow vulnerability
because the software fails to properly bounds-check user-supplied
input before copying it into an insufficiently sized memory buffer.

Remote attackers can exploit this issue to execute arbitrary machine
code in the context of the vulnerable software on the targeted
user's computer.

Dnsmasq is also prone to a NULL-pointer dereference vulnerability.
An attacker can exploit this issue to crash the affected application, denying
service to legitimate users.

NOTE: The TFTP service must be enabled for this issue to be exploitable; this
is not the default.

Versions *prior to* Dnsmasq 2.50 are vulnerable.";


tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100267";
CPE = "cpe:/a:thekelleys:dnsmasq";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36121");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36120");
 script_xref(name : "URL" , value : "http://www.thekelleys.org.uk/dnsmasq/doc.html");
 script_xref(name : "URL" , value : "http://www.coresecurity.com/content/dnsmasq-vulnerabilities");
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 11:12:57 +0200 (Wed, 02 Sep 2009)");
 script_bugtraq_id(36121,36120);
 script_cve_id("CVE-2009-2957","CVE-2009-2958");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Dnsmasq TFTP Service multiple vulnerabilities");

 script_description(desc);
 script_summary("Determine if dnsmasq version is < 2.50");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("dnsmasq_version.nasl");
 script_require_keys("dnsmasq/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

     
include("tftp.inc");
include("version_func.inc");
include("host_details.inc");

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;

dnsPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!get_udp_port_state(dnsPort)){
 exit(0);
}

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:dnsPort))exit(0);

if(version_is_less(version: version, test_version: "2.50")) {

  if (tftp_alive(port:port)) {
    info = string("\n\nINFO: OpenVAs found a running TFTPD at this host. If this is the\ndnsmasq-tftpd, you should disable it immediately until you have\nswitched to the latest version of dnsmasq.\n");
    desc = desc + info;
  } 

      security_hole(port:dnsPort,data: desc);
      exit(0);

}

exit(0);
