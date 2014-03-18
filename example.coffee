
{sign} = require './sign'

{verify} = require './pub_key'

seed = 'shBYCZnEekyeEG2WrZXW6hA6nQ7Hx'
data = 'what in the !@#$ bar! © ® ™ • ½ ¼ ¾ ⅓ ⅔ † ‡ µ ¢ £ € オ サ デ'

# Done in browser
bundle   = sign(seed, data)

# Done on server
# normally you'd get this an `account_info` request
account_info =  {Account: bundle.address}
console.log account_info
# Will check Account and RegularKey fields to see if they match
# public key in the bundle
verified     =  verify(account_info, bundle)

if verified.verified
  console.log "Data verified to be signed with public key matching #{verified.verified} hash/address"
