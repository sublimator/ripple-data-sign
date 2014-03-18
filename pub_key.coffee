################################### REQUIRES ###################################

{
  Seed
  Base
  sjcl
  UInt160
  UInt256
} = require 'ripple-lib'

assert = require 'assert'

Hex   = sjcl.codec.hex
Bytes = sjcl.codec.bytes
Utf8  = sjcl.codec.utf8String

#################################### README ####################################
'''

The purpose of this module is export some kind of api where a client can
ascertain that an arbitrary piece of data was signed by a given public key and
that the public key belongs to a given AccountRoot, by hashing the public key
and comparing against the Account and RegularKey fields.

This requires a version of ripple-lib >= a specific commit:

  commit 007c2e7e5c19d807fa93a205003710fb25153d33
  Author: sublimator <ndudfield@gmail.com>
  Date:   Sat Mar 8 23:37:25 2014 +0700

      Fix typo

'''
################################### CONSTANTS ##################################

SECP_256 = sjcl.ecc.curves.c256

exports.Curve = Curve = do -> 
  order = SECP_256.r
  modulus = SECP_256.field.prototype.modulus

  order: order
  order_bitlength: order.bitLength()
  modulus: SECP_256.field.prototype.modulus
  root_exp: modulus.add(1).div(4)

#################################### CODECS ####################################

bits_2_hex   = (bits)  -> Hex.fromBits(bits)
hex_2_bits   = (hex)   -> Hex.toBits(hex)
bits_2_bytes = (bits)  -> Bytes.fromBits(bits)
bytes_2_bits = (bytes) -> Bytes.toBits(bytes)
bytes_2_bn   = (bytes) -> sjcl.bn.fromBits bytes_2_bits bytes
utf8_to_bits = (str)   -> Utf8.toBits(str)

#################################### HELPERS ###################################

pretty_json = (v) -> 
  JSON.stringify v, undefined, 2

ripemd160_of_sha256 = (bits) ->
  more_bits = sjcl.hash.ripemd160.hash sjcl.hash.sha256.hash(bits)

half_sha_512 = (str) ->
  '''
  @str
    A String, will be utf8 encoded into bytes, then hashed

  @return
    The first 256 bits of a sha512

  '''
  bits = utf8_to_bits str
  hash = sjcl.bitArray.bitSlice(sjcl.hash.sha512.hash(bits), 0, 256)

address_from_pubkey = (hex) ->
  UInt160.from_bits(ripemd160_of_sha256(hex_2_bits(hex)))

################################### SIGNATURE ##################################

exports.Signature = class Signature
  '''

  Represents an ECC ecdsa signature 
  Constructor expects a canonical DER encoding, as hex or an array of bytes.

  '''
  constructor: (der, strict) ->
    # if an array, we assume it's a byte array
    unless Array.isArray(der)
      der = hex_2_bits der
      der = bits_2_bytes der
    
    @parse_der(der, strict ? true)

  rs_bits: ->
    bl = Curve.order_bitlength
    # We use the bit length of the order (256)
    # that means that small values of r/s will be padded
    # also, the verify command assumes order bit ength for each
    sjcl.bitArray.concat(@r.toBits(bl), @s.toBits(bl))

  parse_der: (sig, strict) ->
    sigLen = sig.length
    err_if = (cond, msg) -> throw new Error("Invalid Signature: #{msg}") if cond

    err_if (sigLen < 10) or (sigLen > 74),
           'signature wrong length'
    
    err_if (sig[0] isnt 0x30) or (sig[1] isnt (sigLen - 2)),
           'invalid format'

    # Find R and check its length
    rPos = 4
    rLen = sig[3]
    err_if (rLen < 2) or ((rLen + 6) > sigLen),
           'invalid r length'

    # Find S and check its length
    sPos = rLen + 6
    sLen = sig[rLen + 5]
    err_if (sLen < 2) or ((rLen + sLen + 6) isnt sigLen),
           'invalid s length'
          
    err_if (sig[rPos - 2] isnt 0x02) or (sig[sPos - 2] isnt 0x02),
           'r or s have wrong type'

    err_if not (sig[rPos] & 0x80) is 0,
           'r is negative'

    err_if (sig[rPos] is 0) and ((sig[rPos + 1] & 0x80) is 0),
           'r is padded'

    err_if not (sig[sPos] & 0x80) is 0,
           's is negative'

    err_if (sig[sPos] is 0) and ((sig[sPos + 1] & 0x80) is 0),
           's is padded'

    r = bytes_2_bn(sig.slice(rPos, rPos + rLen))
    s = bytes_2_bn(sig.slice(sPos, sPos + sLen))

    @r = r
    @s = s

    err_if (not Curve.order.greaterEquals(r) or 
            not Curve.order.greaterEquals(s)),
           'r or s not less than modulus/order'

    # order - s should bigger but not equal to s
    # if s is not bigger, than it's inversion, then we are in good order
    err_if strict and (s.greaterEquals(Curve.order.sub(s))),
           's != min(s, n-s)'

################################## PUBLIC KEY ##################################

exports.PublicKey = class PublicKey
  constructor: (pub_key_hex) ->
    '''
    @pub_key_hex
      hex encoded string
      the public key point on the secp256k curve in compressed form

    '''
    @address = address_from_pubkey pub_key_hex
    @pub_point = PublicKey.decompress(pub_key_hex)
    @pub_key = new sjcl.ecc.ecdsa.publicKey(SECP_256, @pub_point)
    @hash_func = half_sha_512

  @decompress = (hex) ->
    throw new Error("invalid pubkey") unless hex.length <= 66
    w        = sjcl.bitArray

    curve    = SECP_256
    pub_bits = hex_2_bits hex
    was_odd  = w.extract(pub_bits, 0, 8) & 0x01
    x        = curve.field.fromBits(w.bitSlice(pub_bits, 8))

    q = Curve.modulus # prime modulus
    a = curve.a
    b = curve.b

    y = x.mul(x.square().add(a)).add(b).power(Curve.root_exp)
    # We need below
    y.fullReduce()
    # isOdd = Number(y.mod(2).equals(1))
    # perf hack
    is_odd = y.limbs[0] & 0x01
    y = new curve.field q.sub(y) if is_odd != was_odd
    p = new sjcl.ecc.point(curve, x, y)

  account_signed: (account_info, data, sig) ->
    '''

    @account_info
      An `AccountRoot` as returned by `account_info` rpc command
      Contains 

      Fields:
        Account
          str
          A ripple address, ie a base58 encode hash of a public key

        RegularKey
          str
          A ripple address, ie a base58 encode hash of a public key

    @data
      string
      the data signed with the private key matching the address
      uses @hash_func, typically half_sha_512 of utf8 encoded str

    @sig
      hex encoded string
      the der encoded signature
      must be in canonical form

    @return
      {
          "verified" : "AccountRoot"|"RegularKey"|false
          "reason" : "$reason"|undefined
      }

    '''
    check = {verified: false, reason: "Account or RegularKey not set"}

    for address in ['Account', 'RegularKey']
      if account_info[address]?
        check = @address_signed(account_info[address], data, sig)
        if check.verified
          check.verified = address
          break

    return check

  signed: (data, sig) ->
    data_bits = hex_2_bits data_bits

  address_signed: (address, data, sig) ->
    '''

    @address
      eg. an Account or RegularKey in an AccountRoot
      base58 encoded string
      eg. 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'

    @data
      string
      the data signed with the private key matching the address
      uses @hash_func, typically half_sha_512 of utf8 encoded str

    @sig
      hex encoded string
      the der encoded signature
      must be in canonical form

    '''
    address = UInt160.from_json(address)

    # Step one is checking pubkey is for the address
    if not address.equals(@address)
      return {verified: false, reason: "pubkey_address_mismatch"}

    try
      der = new Signature(sig, false)
    catch e
      console.info "error while decoding sig", e.toString()
      return {verified: false, reason: "invalid_signature", e: String(e)}

    try
      @pub_key.verify(@hash_func(data), der.rs_bits())
      return {verified: true}
    catch e
      console.info "error while verifying", e.toString()
      # TODO
      return {verified: false, reason: "pubkey_sig_mismatch", e: String(e)}

#################################### VERIFY ####################################

exports.verify = (account_info, bundle) ->
  '''

  Simple boolean returning function, complementary to `sign` which takes
  returned `bundle` 

  '''
  {address, pub_key, data, sig} = bundle
  pk = new PublicKey(pub_key)
  return pk.account_signed(account_info, data, sig)
