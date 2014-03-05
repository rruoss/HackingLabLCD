###############################################################################
# OpenVAS Vulnerability Test
# $Id: ping_host.nasl 72 2013-11-21 17:10:44Z mime $
#
# Ping Host 
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
tag_summary = "This plugin try to determine if the remote host is up.";

if (description)
{
 script_id(100315);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 72 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Ping Host");

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary("Ping the remote host");
 script_category(ACT_SCANNER);
 script_family("Port scanners");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");

 script_add_preference(name:"Use nmap", type:"checkbox", value:"yes");

 script_add_preference(name:"Report about unrechable Hosts", type:"checkbox", value:"no");
 script_add_preference(name:"Report about reachable Hosts", type:"checkbox", value:"no");
 script_add_preference(name:"Mark unrechable Hosts as dead (not scanning)", type:"checkbox", value:"no");
 script_add_preference(name:"Use ARP", type:"checkbox", value:"yes");
 script_add_preference(name:"Do a TCP ping", type:"checkbox", value:"yes");
 script_add_preference(name:"Do an ICMP ping", type:"checkbox", value:"yes");
 script_add_preference(name:"nmap additional ports for -PA", type:"entry", value: "8080,3128");
 script_add_preference(name:"nmap: try also with only -sP", type:"checkbox", value: "no");

 script_dependencies("toolcheck.nasl");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

function IP_IS_IPV6(ip) {

 if(":" >< ip) {
   return TRUE;
 }

 return FALSE;

}

function check_pa_port_list(list) {

  if(!list) return FALSE;

  ports = split(list, sep:",", keep:FALSE);

  foreach port (ports) {

    if(!ereg(pattern:"^[0-9]{1,5}$", string:port)) {
      return FALSE;
    }  

    if(int(port) > 65535) return FALSE;

  }  

  return TRUE;

}  

use_nmap    = script_get_preference("Use nmap"); 
report_dead = script_get_preference("Report about unrechable Hosts");
mark_dead   = script_get_preference("Mark unrechable Hosts as dead (not scanning)");
icmp_ping   = script_get_preference("Do an ICMP ping");
tcp_ping    = script_get_preference("Do a TCP ping");
arp_ping    = script_get_preference("Use ARP"); 
sp_only     = script_get_preference("nmap: try also with only -sP");
report_up   = script_get_preference("Report about reachable Hosts");

set_kb_item(name: "/ping_host/mark_dead", value: mark_dead);
set_kb_item(name: "/tmp/start_time", value: unixtime());

if(islocalhost())exit(0);

if(IP_IS_IPV6(ip:get_host_ip())) {
  if(!defined_func("forge_icmp_v6_packet") && "yes" >!< use_nmap) {
    if("yes" >< report_dead || "yes" >< mark_dead) {
      log_message(data: "ping_host.nasl not launched because target is IPv6 and the installed version of openvas-libraries does not support IPv6. Update to newer openvas-libraries to get IPv6 support.");
    }
   exit(0);
  }
}  

if("no" >< icmp_ping && "no" >< tcp_ping && "no" >< arp_ping && "no" >< sp_only) {
    log_message(data: "ping_host.nasl not launched because all methods are disabled");
    exit(0);
}  

if("no" >< mark_dead && "no" >< report_dead)exit(0);

if("yes" >< use_nmap && !find_in_path('nmap')) {

  log_message(data: 'Nmap was selected for host discovery but is not present on this system.\nFalling back to build in discovery method.');
  use_nmap = 'no';

}  

if("yes" >< use_nmap) {

  argv[x++] = 'nmap';
  argv[x++] = '-sP';

  if("yes" >!< arp_ping)
    argv[x++] = "--send-ip";

  ip = get_host_ip();

  pattern = "Host.*(is|appears to be) up";

  if(IP_IS_IPV6(ip:ip)) {
    argv[x++] = "-6";
  }

  if("yes" >< sp_only) {

    argv_sp_only = argv;
    argv_sp_only[x++] = ip;

    res = pread(cmd: "nmap", argv: argv_sp_only);
    if(res && egrep(pattern:pattern, string:res) && "Host seems down" >!< res) {
      if("yes" >< report_up) {
        log_message(data:"Host is up", port:0);
      }  
      set_kb_item(name: "/tmp/ping/ICMP", value: 1);
      exit(0);
    }  
  }  

  if("yes" >< icmp_ping || "yes" >< arp_ping) {

     argv_icmp = argv;
     argv_icmp[x++] = "-PE";
     argv_icmp[x++] = ip;

     res = pread(cmd: "nmap", argv: argv_icmp);
     if(res && egrep(pattern:pattern, string:res) && "Host seems down" >!< res) {
       if("yes" >< report_up) {
         log_message(data:"Host is up", port:0);
       }
       set_kb_item(name: "/tmp/ping/ICMP", value: 1);
       exit(0);
     }  

  }

  if("yes" >< tcp_ping) {

    argv_tcp = argv;

    pa_ports = '21,22,23,25,53,80,135,137,139,143,443,445';
    nmap_pa_additional_ports = script_get_preference("nmap additional ports for -PA");

    if(strlen(nmap_pa_additional_ports) > 0) {
      nmap_pa_additional_ports = str_replace(string:nmap_pa_additional_ports, find:" ", replace:"");
      if(!check_pa_port_list(list:nmap_pa_additional_ports)) {
        log_message(port:0, data:'nmap additional ports for -PA has wrong format or contains an inalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: 8080,3128,8000');
        nmap_pa_additional_ports = '';
      } else { 
        pa_ports += ',' + nmap_pa_additional_ports;
      }  
    }  

    argv_tcp[x++] = '-PA' + pa_ports;
    argv_tcp[x++] = ip;

    res = pread(cmd: "nmap", argv: argv_tcp);
    if(res && egrep(pattern:pattern, string:res) && "Host seems down" >!< res) {
      if("yes" >< report_up) {
        log_message(data:"Host is up", port:0);
      }
      set_kb_item(name: "/tmp/ping/TCP", value: 1);
      exit(0);
    }  
  }  

} else {  

  if("yes" >< icmp_ping) {
    # Try ICMP (Ping) first
    if(IP_IS_IPV6(ip:get_host_ip())) {
      # ICMPv6
      IP6_v = 0x60;
      IP6_P = 0x3a;#ICMPv6
      IP6_HLIM = 0x40;
      ICMP_ID = rand() % 65536;

      myhost = this_host();

      ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                                     ip6_p: IP6_P,
                                     ip6_plen: 20,
                                     ip6_hlim: IP6_HLIM,
                                     ip6_src: myhost,
                                     ip6_dst: get_host_ip());
      d = rand_str(length: 56);
      icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:128, icmp_code:0, icmp_seq:0,
                                icmp_id: ICMP_ID, icmp_cksum:-1, data: d);
  
      filter = "icmp6 and dst host " + myhost + " and src host " + get_host_ip()  + " and ip6[40] = 129";
  
      ret = NULL;
      attempt = 2;

      while (!ret && attempt--) {
        ret = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
        if(ret) { 
          if("yes" >< report_up) {
            log_message(data:"Host is up", port:0);
          }
          set_kb_item(name: "/tmp/ping/ICMP", value: 1);
          exit(0);
        }
      }

    } else {  
      # ICMPv4
      ICMP_ECHO_REQUEST = 8;
      IP_ID = 0xBABA;
      ICMP_ID = rand() % 65536;

      data =
      raw_string(0x0c,0xf5,0xf3,0x4a,0x88,0x39,0x08,0x00,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
      	         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
 	         0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
  	         0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37);

      ip_packet =
              forge_ip_packet(ip_tos : 6,
                              ip_id  : IP_ID,
                              ip_off : IP_DF,
                              ip_p   : IPPROTO_ICMP,
                              ip_src : this_host());

      icmp_packet =
             forge_icmp_packet(icmp_type : ICMP_ECHO_REQUEST,
                               icmp_code : 123,
                               icmp_seq  : 256,
                               icmp_id   : ICMP_ID,
                               data      : data,
                               ip        : ip_packet);
      attempt = 2;
      ret = NULL;

      filter = "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 0 " + " and icmp[4:2] = " + ICMP_ID;

      while (!ret && attempt--) {
       ret = send_packet(icmp_packet, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 3);
       if(ret) {
        if("yes" >< report_up) {
          log_message(data:"Host is up", port:0);
        }
        set_kb_item(name: "/tmp/ping/ICMP", value: 1);
        exit(0);
       }
      }
    }

  }  

  if("yes" >< tcp_ping) {
    # ICMP fails. Try TCP SYN 
    if(tcp_ping()) {
      if("yes" >< report_up) {
        log_message(data:"Host is up", port:0);
      }
      set_kb_item(name: "/tmp/ping/TCP", value: 1);
      exit(0);
    }  
  }
}  
# Host seems to be dead.

if("yes" >< report_dead) {
  data = string("The remote host ", get_host_ip(), " was considered as dead.\n");
  log_message(data:data, port:0);
}

if("yes" >< mark_dead) {
  set_kb_item(name:"Host/ping_failed", value: 1);
}  

exit(0);

