"""Independent vector generator. Run with Python and pycryptodome, without Rust codecs."""
from Crypto.Hash import keccak


def hash_bytes(value):
    return keccak.new(digest_bits=256, data=value).digest()


def integer(value):
    return value.to_bytes(32, "big")


def address(byte):
    return bytes(12) + bytes([byte]) * 20


def struct(type_string, *words):
    return hash_bytes(hash_bytes(type_string.encode()) + b"".join(words))


domain = struct(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    hash_bytes(b"TempoZoneAccess"), hash_bytes(b"1"), integer(42431), address(0x11),
)
token = struct(
    "AccessToken(uint32 zoneId,uint64 zoneChainId,address principal,uint8 credentialKind,uint64 clientGeneration,bytes32 tokenId,string label,uint64 issuedAt,uint64 expiresAt)",
    integer(42), integer(1337), address(0x22), integer(2), integer(7),
    bytes([0x33]) * 32, hash_bytes(b"audit"), integer(1700000000), integer(1700000600),
)
admit = struct(
    "Admission(string name,uint8 scopes,bool allAccounts,address[] accounts)",
    hash_bytes(b"auditor"), integer(5), integer(0), hash_bytes(address(0x44) + address(0x55)),
)
op = struct(
    "AccessOperation(uint32 zoneId,uint64 zoneChainId,address client,uint64 sequence,uint64 generation,address signer,uint64 signerGeneration,uint8 changeTag,bytes32 changeHash,uint64 issuedAt,uint64 expiresAt)",
    integer(42), integer(1337), address(0x22), integer(1), integer(0), address(0x66),
    integer(0), integer(0), admit, integer(1700000000), integer(1700000600),
)
print("token", hash_bytes(b"\x19\x01" + domain + token).hex())
print("admit op", hash_bytes(b"\x19\x01" + domain + op).hex())
