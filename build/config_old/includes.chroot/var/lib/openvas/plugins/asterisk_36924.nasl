###############################################################################
# OpenVAS Vulnerability Test
# $Id: asterisk_36924.nasl 15 2013-10-27 12:49:54Z jan $
#
# Asterisk SIP Response Username Enumeration Remote Information Disclosure Vulnerability
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
tag_summary = "Asterisk is prone to an information-disclosure vulnerability because
it doesn't provide safe responses to failed authentication attempts.

Attackers can exploit this issue to discover whether specific
usernames exist. Information harvested may aid in launching
further attacks.";


tag_solution = "The vendor has released an advisory and updates. Please see the
references for details.";

if (description)
{
 script_id(100341);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-10 12:45:58 +0100 (Tue, 10 Nov 2009)");
 script_bugtraq_id(36924);
 script_cve_id("CVE-2009-3727");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Asterisk SIP Response Username Enumeration Remote Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36924");
 script_xref(name : "URL" , value : "http://www.asterisk.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/507688");
 script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2009-008.html");

 script_description(desc);
 script_summary("Determine if Asterisk is prone to an information-disclosure vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_asterisk_detect.nasl");
 script_require_keys("Services/udp/sip");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("version_func.inc");

asterisk_port = get_kb_item("Services/udp/sip");
if(!asterisk_port)exit(0);
if(!get_udp_port_state(asterisk_port))exit(0);

asteriskVer = get_kb_item("Asterisk-PBX/Ver");
if(!asteriskVer){
      exit(0);
}

if(version_in_range(version:asteriskVer, test_version:"1.6.1",  test_version2:"1.6.1.8")  ||
   version_in_range(version:asteriskVer, test_version:"1.6",    test_version2:"1.6.16")   ||
   version_in_range(version:asteriskVer, test_version:"1.4.26", test_version2:"1.4.26.2") ||
   version_in_range(version:asteriskVer, test_version:"1.2",    test_version2:"1.2.34")) {

    security_warning(port:asterisk_port, proto:"udp");
    exit(0);

}

exit(0);
