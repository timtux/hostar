#!/usr/bin/env ruby
#
# hostar.rb - Host/web discovery 
#
# Probe DNS and Bing API to discover websites/hosts in a IP-range even 
# tho offline. Requires you to have a bing api key. Get one free at
# http://www.bing.com/developers/ (5000requests/month)
#
MICROSOFT_BING_API_KEY = "FGHJKLJHGFCVHBJKLJHGFCVHBJNK"
#
# Copyright (c) 2012 Tim Jansson
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
require 'trollop'
require 'resolv'
require 'net/http'
require 'uri'
require 'ipaddr'

########################################################################################
# Commandos. Using Trollop Gem.
########################################################################################
ARGV[1] = '--help' if ARGV.empty?

opts = Trollop::options do
  version "\nHostar 0.1 (c) 2012 Tim Jansson <tim@timtux.net>\n"

  banner "Hostar 0.1 <tim@timtux.net>"

  banner "\n  Usage: ./hostar [Options] {range/target specification}"
  banner "Example: ./hostar -b -f 192.168.1.1 -t 192.168.1.2\n "
  
  opt :regex_filter, "Filter out hosts matching this regular expression",
      :type => String

  opt :disable_bing, "Disable Bing API lookup", :short => "-b",
      :default => false

  opt :from, "From IP-address. Eg. -f 192.168.1.83",
      :type => String,
      :required => false
      
  opt :to, "To IP-address. Eg. -t 192.168.2.23",
      :type => String,
      :required => false
      
  opt :domain, "Domain to resolv and check",
      :type => String,
      :required => false  

end

########################################################################################
# Argument validation and parsing
########################################################################################
ip_regex = /^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])/

# Domain lookup if provided
if opts[:domain]
  begin
    opts[:from] = Resolv.getaddress(opts[:domain])
    opts[:to]   = Resolv.getaddress(opts[:domain])
  rescue 
    Trollop::die :domain, "Could not resolv domain provided"
  end
end

# Regex validation
begin
  Regexp.new(/#{opts[:regex_filter]}/) 
rescue RegexpError 
  Trollop::die :regex_filter, "Invalid regular expression"
end

# Ip Validation
Trollop::die :from, "Must be an IP-address" if !opts[:from].to_s.scan(ip_regex)[0]
Trollop::die :to, "Must be an IP-address" if !opts[:to].to_s.scan(ip_regex)[0]

# Parse arguments
from_addr     = IPAddr.new(opts[:from])
to_addr       = IPAddr.new(opts[:to])

# Check for valid ip range
Trollop::die :to, "Invalid IP-range" if to_addr < from_addr

########################################################################################
# The show must go on. COLLECT ALL THE DATA!
########################################################################################
hosts       = {}
current_ip  = from_addr

while current_ip <= to_addr
  # Reverse DNS
  begin 
    current_hostname        = Resolv.getname(current_ip.to_s)
    
    if current_hostname.length < 2
      # Do nothing....
    elsif hosts[:"#{current_ip}"].nil? 
      hosts[:"#{current_ip}"] = {:"#{current_hostname}" => 'Reverse DNS'}
    else 
      hosts[:"#{current_ip}"][:"#{current_hostname}"] = 'Reverse DNS'
    end
  rescue Exception => e 
  end

  # API
  if !opts[:disable_bing]
    url = "https://api.datamarket.azure.com/Data.ashx/Bing/Search/v1/Web?Query='ip:#{current_ip}'&$top=50&$format=Atom"
    uri = URI.parse(url)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    request.basic_auth(nil, MICROSOFT_BING_API_KEY)

    http.request(request).body.scan(/<d:Url m:type="Edm\.String">([^\\?<]*)/).each do |x| 
      if x[0].length > 3
          found_host = URI.parse(URI.encode(x[0])).host
    
          if found_host.match(ip_regex)
            next # We don't want any IPs in hosts.
          elsif hosts[:"#{current_ip}"].nil? 
            hosts[:"#{current_ip}"] = {:"#{found_host}" => 'API'}
          else 
            hosts[:"#{current_ip}"][:"#{found_host}"] = 'API'
          end
      end
    end
  end
  
  current_ip = current_ip.succ
end

########################################################################################
# Start output
########################################################################################
ip_count    = 0
host_count  = 0

puts "--------------------------------------------------------------------------------"
puts "|%15s |%43s |%15s |" % ["IP-Address", "Hostname", "Source"]
puts "--------------------------------------------------------------------------------"
hosts.each do |ip,val|  
  val.each do |hostname,source|
    if !opts[:regex_filter] || !hostname.match(/#{opts[:regex_filter]}/)
       puts "|%15s |%43s |%15s |" % [ip, hostname, source]
       host_count = host_count + 1
    end
  end
  
  ip_count = ip_count + 1
end
puts "--------------------------------------------------------------------------------"
puts "|%36s | %38s |" % ["IP Count: #{ip_count}", "Hostname Count: #{host_count}"]
puts "--------------------------------------------------------------------------------"