import base64
import re
from Crypto.PublicKey import RSA
from gensim.utils import unpickle


class keywrap:
    def __init__(self,key_length=None,unpickle=False):
        if unpickle:
            self.dummy=False
            self.key=self.unpickleKey()
            self.public_key=self.key.publickey()
        elif key_length:
            self.dummy=False
            self.key = RSA.generate(key_length)
            self.public_key = self.key.publickey()
        else:
            self.dummy=True
    def encrypt(self,msg):
        #takes in hex/text outputs hex
        if self.dummy:
            return msg
        return self.key.encrypt(msg,self.public_key)[0]
    def decrypt(self,enc):
        if self.dummy:
            return enc
        return self.key.decrypt(enc)
    def exportedPK(self):
        return self.public_key.exportKey
    def pickleKey(self): # should serialize private key somewhere
        pass
    def unpickleKey(self):
        pass
    def importPublic(self,k):
        pass # gets key from website
    def importPrivate(self):
        pass # should use pickle

class UniMapper:
    def __init__(self,enc='chinese'):
        if enc=='chinese':
            self.ranges= [int(x,16) for x in ['4E00','9FCC','20000','2A6DF','3400','4DB5']] #from,to,from,to
        else:
            self.ranges =[int(x,16) for x in ['0021','FEFE','FF01','FFFD','20000', "2A6DF"]]

    def transform(self,number, inverse=False):
        r = self.ranges
        intervals = [(r[aye],r[aye+1],r[aye+1]-r[aye]) for aye in range(0,len(r),2)]
        if inverse:
            temp=0
            for fro,to,intv in intervals:
                if fro<number<to:
                    return temp+number-fro
                else:
                    temp+=intv
#                    number-=intv
            return number,intv,to,fro,'inverse'
        else:
            for fro,to,intv in intervals:
#                print fro,to,intv,number
                if number>intv:
                    number-=intv
                else:
                    return fro+number
            return number,intv,to,fro,'nonverse'

    def chinese2hex(self,cstr):
        """
        @param Cstr: the "chinese" text , uncode codepoints.
        @return: a list bytes to be decrypted
        """
        def c2h(num):
            nums= self.transform(num,inverse=True)
            return map(chr,divmod(nums,256))
        temp= ''.join(sum(map(c2h,cstr),[]))
#        print temp,temp[-3:],len('\xfd\xff\xfe')
        if temp[-3:]=='\xfd\xff\xfe':
            return temp[:-3]
        return temp
    # takes hex string , outputs unicode code points.
    def hex2unicode(self,bksldhx_data):
        if len(bksldhx_data)%2:
            bksldhx_data+='\xfd\xff\xfe'
        numbers = [ord(a)*256+ord(b) for a,b in zip(bksldhx_data[::2],bksldhx_data[1::2]) ]
        #numbers = [(1) for a,b in zip(bksldhx_data[0][::2],bksldhx_data[0][1::2]) ]
        numbers = [self.transform(n) for n in numbers]
        return numbers
    def key_to_unichr(self,key):
        mk = key.exportKey().split('\n')
        whittled=''.join(mk[1:-1])
        k= base64.b64decode(whittled)
        self.before, self.after=mk[0],mk[-1]
        return self.hex2unicode(k)
    def unichr_to_key(self,unc):
        k=re.findall('(.{,64})',self.chinese2hex(unc))
        return '\n'.join([self.before]+k+[self.after])
class tweetwrap:
    def __init__(self):
        self.auth=[]
    def post(self,unimsg):
        pass
    def read(self,author):
        return 'a'

if __name__=="__main__":
    print 'example:'
    if True:
        keyw = keywrap(2048)
        keyw.pickleKey()
    else:
        keyw=keywrap(unpickle=True)

    u = UniMapper(None)#default is "chinese"
    message = 'hello'
    print message
    enc = keyw.encrypt(message)
    print enc
    a=u.hex2unicode(enc) # currently this returns numbers because i need to either rebuild python or use python 3 to get unicode code points above 0x10000
    print a,max(a)
    b = u.chinese2hex(a)
    print b
    dec = keyw.decrypt(b)
    print dec

    msg2 = 'asdfg'

