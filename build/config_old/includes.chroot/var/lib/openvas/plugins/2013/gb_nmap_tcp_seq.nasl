###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_tcp_seq.nasl 11 2013-10-27 10:12:02Z jan $
#
# TCP/IP Predictable TCP Initial Sequence Number Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "The remote host has predictable TCP sequence numbers. 
A cracker may use this flaw to spoof TCP connections";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103701";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(670,107);
 script_cve_id("CVE-1999-0077","CVE-2000-0916","CVE-2001-0288");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("TCP/IP Predictable TCP Initial Sequence Number Vulnerability");

desc = "
 Summary:
 " + tag_summary;
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/670");
 script_xref(name:"URL", value:"http://teso.scene.at/");
 script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010301-ios-tcp-isn-random");
 script_xref(name:"URL", value:"http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0077");
 script_xref(name:"URL", value:"ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-00:52.tcp-iss.asc");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-22 11:14:29 +0200 (Mon, 22 Apr 2013)");
 script_description(desc);
 script_summary("Determine if the remote host has predictable TCP sequence numbers");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_require_keys("Host/tcp_seq");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

tcp_seq = get_kb_item("Host/tcp_seq");
if(!tcp_seq)exit(0);

if(tcp_seq == "constant") {

  security_hole(port: 0, data: "The TCP sequence numbers of the remote host are constant ! A cracker may use this flaw
                                to spoof TCP connections easily. 
                                Solution : contact your vendor for a patch");

}  

else if(tcp_seq == "800") {

  security_hole(port: 0, data: "The TCP sequence numbers of the remote host are always incremented by 800, so they can
                                be guessed rather easily. A cracker may use this flaw to spoof TCP connections easily.
                                Solution : contact your vendor for a patch");

}

else if(tcp_seq == "64000") {

  security_hole(port: 0, data: "The TCP sequence numbers of the remote host are always incremented by 64000, so they can
                                be guessed rather easily. A cracker may use this flaw to spoof TCP connections easily.
                                Solution : contact your vendor for a patch");

}

else if(tcp_seq == "time") {

  security_hole(port: 0, data: "The TCP sequence numbers of the remote host depends on the time, so they can be guessed
                                rather easily. A cracker may use this flaw to spoof TCP connections easily.
                                Solution : http://www.microsoft.com/technet/security/bulletin/ms99-046.asp");

}

exit(99);
