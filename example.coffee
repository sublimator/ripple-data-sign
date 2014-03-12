# Used by client
{sign} = require './sign'
# Used on server
{verify} = require './pub_key'

seed = 'shBYCZnEekyeEG2WrZXW6hA6nQ7Hx'
data = 'what in the !@#$ bar! © ® ™ • ½ ¼ ¾ ⅓ ⅔ † ‡ µ ¢ £ € オ サ デ'

bundle   = sign(seed, data)
verified = verify(bundle)

# console.log 'verified', verified