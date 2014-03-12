################################### REQUIRES ###################################

# Used by client
{sign} = require '../sign'
# Used on server
{verify, PublicKey, Curve} = require '../pub_key'
{Seed} = require 'ripple-lib'

assert = require 'assert'

##################################### TESTS ####################################

seeds = [ 'ssmzDSQmFVf2ibXgWRcBixD9vxSPd',
          'saDMj89wc1T28SfyuuXpmy7uo6oy2',
          'shsPtzuTwMS9igyhRzBvRW8VPVQKH',
          'ssncHf843HaPrV5ASKFaPLfdFMEyD',
          'shVhsMDVmBBkeg1U1rFrFDuoCE2Gv',
          'ssK8ZsVjXxASrNLr2UdvZzTp1Ugj3',
          'shyt9YEBzwHXrAFN6jH9G9b1p17kC',
          'ss8THiLyYYSuaLVrvK3gY8dwmDSH2',
          'snuPQvxqBPmhqB9BJMKAhRLe16BXQ',
          'shV6ssvH7V3Y4opZH5T5veyJrcCRj' ]

suite "ripple-data", ->
  suite "verify/sign", ->
    make_test = (passphrase) ->
      seed = Seed.from_json(passphrase).to_json()

      test "hi level helpers work with #{seed}", ->
        data = 'what in the !@#$ bar! © ® ™ • ½ ¼ ¾ ⅓ ⅔ † ‡ µ ¢ £ € オ サ デ'

        bundle   = sign(seed, data)
        verified = verify(bundle)
        assert verified

    make_test "shBYCZnEekyeEG2WrZXW6hA6nQ7Hx"
    make_test s for s in seeds

  suite "PublicKey", ->
    suite "decompressing points", ->
      make_test = (seed) ->
        seed = Seed.from_json(seed)
        seed_json = seed.to_json()

        test "decompressing pub_key for #{seed_json}", ->
          key_pair = seed.get_key()
          point = key_pair._pub()._point
          pub_key_hex = key_pair.to_hex_pub()
          decompressed = PublicKey.decompress(pub_key_hex)

          assert_points_equal = (ord) ->
            actual = decompressed[ord]
            expected = point[ord]
            is_equal = actual.equals(expected)

            if not is_equal and ord == 'y' and Curve.modulus.sub(actual).equals expected
              console.log 'needs inverting'

            assert is_equal, "#{ord} is wrong, expected: #{expected}, got: #{actual}"

          assert_points_equal 'x'
          assert_points_equal 'y'

      make_test "shBYCZnEekyeEG2WrZXW6hA6nQ7Hx"
      make_test s for s in seeds
      # make_test s for s in ("passphrase#{i}" for i in [20..100])
