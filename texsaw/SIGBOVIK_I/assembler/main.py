import sys
import os
from dataclasses import dataclass


@dataclass
class Char:
    value: str

    def __post_init__(self):
        assert len(self.value) == 1


class Unspecified:
    pass


def opcode_from_mnemonic(mnem: str) -> int:
    match mnem.upper():
        case "LOAD":
            return 0x10AD000
        case "PRIMAPPLY":
            return 0x9A99000
        case "JUMP":
            return 0x70AD000
        case "CJUMP":
            return 0xCA7000
        case "GET":
            return 0x9E7000
        case "FORGET":
            return 0x49E7000
        case "APPLY":
            return 0xA991000
        case "TAILAPPLY":
            return 0x7991000
        case "ADD":
            return 0x0ADD000
        case "SUB":
            return 0x050B000
        case "MUL":
            return 0x0A55000
        case "LT":
            return 0x1700000
        case "EQ":
            return 0xE3E3000
        case "EQP":
            return 0x3E3E000
        case "ZEROP":
            return 0xEEEE000
        case "STRING":
            return 0x571F000
        case "STRINGREF":
            return 0x571E000
        case "STRINGSET":
            return 0x5715000
        case "STRINGAPPEND":
            return 0x571A000
        case "VECTOR":
            return 0x5ECF000
        case "VECTORREF":
            return 0x5ECE000
        case "VECTORSET":
            return 0x5EC5000
        case "VECTORAPPEND":
            return 0x5ECA000
        case "INTEGERP":
            return 0x1234000
        case "BOOLEANP":
            return 0xB001000
        case "CHARP":
            return 0xCACA000
        case "NULLP":
            return 0x4321000
        case "NOT":
            return 0x7777000
        case "INTTOCHAR":
            return 0x170C000
        case "CHARTOINT":
            return 0xC701000
        case "FRAME":
            return 0x57AC000
        case "CONS":
            return 0xC0C0000
        case "CAR":
            return 0xCA00000
        case "CDR":
            return 0xCD00000
        case "LAMBDA":
            return 0xBAAA000
        case "CALL":
            return 0xCA11000
        case "TAILCALL":
            return 0x7A11000
        case "RETURN":
            return 0xDB22000
        case "DONE":
            return 0xD0D0000
    raise ValueError(f"Unrecognized mnemonic {mnem!r}")


Immediate = int | bool | Char | None | Unspecified

CHAR_PREFIX: str = "#\\"


def parse_immediate(s: str) -> Immediate:
    match s:
        case "#f" | "#F":
            return False
        case "#t" | "#T":
            return True
        case "NULL":
            return None
        case "UNSPECIFIED":
            return Unspecified()

    if s.isnumeric() and s.isascii():
        result: int = int(s)
        if result < 0 or result > 2**62 - 1:
            raise ValueError("Integer {result} out of range")
        return result

    if s.startswith(CHAR_PREFIX):
        char_data: str = s[len(CHAR_PREFIX) :]
        if len(char_data) == 1 and char_data.isascii():
            return Char(char_data)
        elif len(char_data) == 3 and char_data[0] == "x" and char_data.isascii():
            return Char(chr(int(char_data[1:], 16)))
        raise ValueError(
            f"Couldn't parse character constant {s} (not all are supported yet)"
        )

    raise ValueError(f"Couldn't parse immediate {s}")


def serialize_immediate(v: Immediate) -> bytes:
    if isinstance(v, bool):
        return (0b10011111 if v else 0b00011111).to_bytes(8, "little")
    if isinstance(v, int):
        return (v << 2).to_bytes(8, "little")
    if isinstance(v, Char):
        return ((ord(v.value) << 8) | 0b00001111).to_bytes(8, "little")
    if v is None:
        return 0b00101111.to_bytes(8, "little")
    if isinstance(v, Unspecified):
        return 0xFFFFFFFFFFFFFFFF.to_bytes(8, "little")
    assert False


DEFAULT_IMMEDIATE: bytes = 0x0.to_bytes(8, "little")


def main() -> None:
    for line in filter(lambda l: l.strip(), sys.stdin.readlines()):
        opcode: int | None = None
        immediate: bytes = DEFAULT_IMMEDIATE
        split_line: list[str] = line.split()
        if "//" in split_line:
            split_line = split_line[: split_line.index("//")]
        match split_line:
            case ["LOAD", v]:
                immediate = serialize_immediate(parse_immediate(v))
            case ["JUMP", v]:
                immediate = int(v).to_bytes(8, "little")
            case ["CJUMP", v]:
                immediate = int(v).to_bytes(8, "little")
            case ["PRIMAPPLY", m]:
                immediate = opcode_from_mnemonic(m).to_bytes(8, "little")
            case ["GET", v]:
                immediate = int(v).to_bytes(8, "little")
            case ["LAMBDA", v]:
                immediate = int(v).to_bytes(8, "little")
        os.write(
            1, opcode_from_mnemonic(split_line[0]).to_bytes(8, "little") + immediate
        )


if __name__ == "__main__":
    main()
