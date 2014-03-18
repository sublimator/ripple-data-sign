################################### REQUIRES ###################################

{
  Seed
  sjcl
  UInt256
} = require 'ripple-lib'

HexCodec = sjcl.codec.hex
Utf8Codec = sjcl.codec.utf8String

#################################### HELPERS ###################################

half_sha_512 = (str) ->
  bits = Utf8Codec.toBits str
  hash = sjcl.bitArray.bitSlice(sjcl.hash.sha512.hash(bits), 0, 256)

#################################### EXPORTS ###################################
 
exports.sign = (secret, data) ->
  '''
 
  @secret
    base58 encoded seed string 
    eg. shVhsMDVmBBkeg1U1rFrFDuoCE2Gv
    (in fact a passphrase will also work, 
     as will anything that Seed.from_json can understand )

  @data
    str (will be utf8 encoded before hashing)
 
  '''
  seed = Seed.from_json secret
  key_pair = seed.get_key()
  address = key_pair.get_address()
  hash = UInt256.from_bits half_sha_512(data)
  der_bits = key_pair.sign(hash)
 
  # return object, use pub_key.verify 
  signed_data_bundle =
    address: address.to_json()
    pub_key: key_pair.to_hex_pub()
    data: data
    sig: HexCodec.fromBits der_bits