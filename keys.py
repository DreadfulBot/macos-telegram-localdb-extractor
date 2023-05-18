# install pycryptodome or pycryptodomex
# python3.11 -m pip3 install mmh3 pycryptodome pycryptodomex

# brew install sqlcipher
# sqlcipher ~/Library/Group\ Containers/6N38VWS5BX.ru.keepcoder.Telegram/stable/account-*/postbox/db/db_sqlite
# enter a cypher

try:
    from Cryptodome.Hash import SHA512
    from Cryptodome.Cipher import AES
except ImportError:
    from Cryptodome.Hash import SHA512
    from Cryptodome.Cipher import AES
import binascii
import enum
import io
import struct

import mmh3

key_file = '/Users/<USER>/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/appstore/.tempkeyEncrypted'

DEFAULT_PASSWORD = ''


class ByteUtil:
    def __init__(self, buffer, endian='<'):
        self.endian = endian
        self.buf = buffer

    def read_fmt(self, fmt):
        fmt = self.endian + fmt
        data = self.buf.read(struct.calcsize(fmt))
        return struct.unpack(fmt, data)[0]

    def read_int8(self):
        return self.read_fmt('b')

    def read_uint8(self):
        return self.read_fmt('B')

    def read_int32(self):
        return self.read_fmt('i')

    def read_uint32(self):
        return self.read_fmt('I')

    def read_int64(self):
        return self.read_fmt('q')

    def read_uint64(self):
        return self.read_fmt('Q')

    def read_bytes(self):
        slen = self.read_int32()
        return self.buf.read(slen)

    def read_str(self):
        return self.read_bytes().decode('utf-8')

    def read_short_bytes(self):
        slen = self.read_uint8()
        return self.buf.read(slen)

    def read_short_str(self):
        return self.read_short_bytes().decode('utf-8')

    def read_double(self):
        return self.read_fmt('d')


def murmur(d):
    # seed from telegram
    return mmh3.hash(d, seed=-137723950)


class MessageDataFlags(enum.IntFlag):
    GloballyUniqueId = 1 << 0
    GlobalTags = 1 << 1
    GroupingKey = 1 << 2
    GroupInfo = 1 << 3
    LocalTags = 1 << 4
    ThreadId = 1 << 5


class FwdInfoFlags(enum.IntFlag):
    SourceId = 1 << 1
    SourceMessage = 1 << 2
    Signature = 1 << 3
    PsaType = 1 << 4
    Flags = 1 << 5


class MessageFlags(enum.IntFlag):
    Unsent = 1
    Failed = 2
    Incoming = 4
    TopIndexable = 16
    Sending = 32
    CanBeGroupedIntoFeed = 64
    WasScheduled = 128
    CountedAsIncoming = 256


class MessageTags(enum.IntFlag):
    PhotoOrVideo = 1 << 0
    File = 1 << 1
    Music = 1 << 2
    WebPage = 1 << 3
    VoiceOrInstantVideo = 1 << 4
    UnseenPersonalMessage = 1 << 5
    LiveLocation = 1 << 6
    Gif = 1 << 7
    Photo = 1 << 8
    Video = 1 << 9
    Pinned = 1 << 10


class MessageIndex:
    def __init__(self, peerId, namespace, mid, timestamp):
        self.peerId = peerId
        self.namespace = namespace
        self.id = mid
        self.timestamp = timestamp

    @classmethod
    def from_bytes(cls, b):
        bio = ByteUtil(io.BytesIO(b), endian='>')
        peer_id = bio.read_int64()
        namespace = bio.read_int32()
        timestamp = bio.read_int32()
        mid = bio.read_int32()
        return cls(peer_id, namespace, mid, timestamp)

    def as_bytes(self):
        return struct.pack('>qiii', self.peerId, self.namespace, self.timestamp, self.id)

    def __repr__(self):
        return f'ns:{self.namespace} pr:{self.peerId} id:{self.id} ts:{self.timestamp}'


def tempkey_kdf(password):
    h = SHA512.new()
    h.update(password.encode('utf-8'))  # never tried on non-ascii passwords tho
    digest = h.digest()
    key, iv = digest[0:32], digest[-16:]
    return key, iv


def temp_key_parse(dataEnc, pwd):
    aes_key, aesIV = tempkey_kdf(DEFAULT_PASSWORD)
    cipher = AES.new(key=aes_key, iv=aesIV, mode=AES.MODE_CBC)
    data = cipher.decrypt(dataEnc)

    db_key = data[0:32]
    db_salt = data[32:48]
    db_hash = struct.unpack('<i', data[48:52])[0]
    db_pad = data[52:]

    if len(db_pad) != 12 and any(db_pad):
        print('warn: db_pad not 12 zeros')

    calc_hash = murmur(db_key + db_salt)
    if db_hash != calc_hash:
        raise Exception(f'hash mismatch: {db_hash} != {calc_hash}')

    return db_key, db_salt


def temp_key_pragma(db_key, db_salt):
    key = binascii.hexlify(db_key + db_salt).decode('utf-8')
    return '''PRAGMA key="x'{}'"'''.format(key)


with open(key_file, 'rb') as f:
    temp_key_enc = f.read()
    dbKey, dbSalt = temp_key_parse(temp_key_enc, DEFAULT_PASSWORD)
    print(temp_key_pragma(dbKey, dbSalt))
