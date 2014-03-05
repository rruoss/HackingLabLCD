###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_cve_2009_1211.nasl 15 2013-10-27 12:49:54Z jan $
#
# squid information-disclosure vulnerability
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
tag_summary = "According to its version number, the remote version of Squid is prone to an
    information-disclosure vulnerability related to the interpretation of the
    Host HTTP header. Specifically, this issue occurs when the proxy makes a
    forwarding decision based on the Host HTTP header instead of the destination
    IP address.

    Attackers may exploit this issue to obtain sensitive information such as
    internal intranet webpages. Additional attacks may also be possible.

    These issues affect Squid 2.7 and 3.0.";


if(description)
{
  script_id(100147);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(33858);
  script_cve_id("CVE-2009-1211");
  desc = "

  Summary:
  " + tag_summary;

  script_description(desc);
  script_name("Squid information-disclosure vulnerability");
  script_summary("Determines if squid is vulnerable to information-disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 David Maciejak");
  script_family("Firewalls");
  script_dependencies("secpod_squid_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");
port = get_kb_item("Services/http_proxy");

if(!port){
  exit(0);
}

squidVer =get_kb_item(string("www/", port, "/Squid"));

if(!squidVer){
  exit(0);
}

if(egrep(pattern:"(2\.7|3\.0)", string:squidVer))
{
  security_hole(port);
  exit(0);
}

exit(0);
