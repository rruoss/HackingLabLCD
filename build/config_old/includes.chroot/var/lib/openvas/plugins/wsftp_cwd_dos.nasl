# OpenVAS Vulnerability Test
# $Id: wsftp_cwd_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WS FTP CWD DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "According to its version number, your remote WS_FTP server is vulnerable to a
  denial of service.
  A logged attacker submitting a 'CWD' command along with arbitrary characters
  will deny the ftp service.

  ** OpenVAS only checked the version number in the server banner";

tag_solution = "Upgrade to the latest version";

#  Ref : Marc <marc@EEYE.COM>

if(description)
{
  script_id(14586);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(217);
  script_cve_id("CVE-1999-0362");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WS FTP CWD DoS");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Check WS_FTP server version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(! get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port);
if(!banner){
  exit(0);
}
# Checking for the WS_FTP Server 1.0.2
if(egrep(pattern:"WS_FTP Server 1\.0\.[0-2][^0-9]", string: banner)){
  security_warning(port);
}
