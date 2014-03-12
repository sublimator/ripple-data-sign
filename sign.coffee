################################### REQUIRES ###################################

{
  Seed
  sjcl
  UInt256
} = require 'ripple-lib'

HexCodec = sjcl.codec.hex
Utf8Codec = sjcl.codec.utf8String

#################################### HELPERS ###################################

hasher = (str) ->
  bits = Utf8Codec.toBits str
  hash = sjcl.bitArray.bitSlice(sjcl.hash.sha512.hash(bits), 0, 256)

#################################### EXPORTS ###################################
 
exports.sign = (secret, data) ->
  '''
 
  This code is self contained, just needs some requires:
 
 
  @secret
    seed 
 
  @data
    str (will be utf8 encoded before hashing)
 
  '''
  seed = Seed.from_json secret
  key_pair = seed.get_key()
  address = key_pair.get_address()
  hash = UInt256.from_bits hasher(data)
  der_bits = key_pair.sign(hash)
 
  # return object, use PublicKey.verify static method
  signed_data_bundle =
    address: address.to_json()
    pub_key: key_pair.to_hex_pub()
    data: data
    sig: HexCodec.fromBits der_bits