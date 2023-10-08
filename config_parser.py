#!/usr/bin/env python3


from dataclasses import dataclass
import struct
import typing
import types
import textwrap
from enum import IntEnum


from eeprom_config_dumps import *



@dataclass
class ATECC608_SlotConfig:
    read_key: int = None
    no_mac: bool = None
    limited_use: bool = None
    encrypt_read: bool = None
    is_secret: bool = None
    write_key: int = None
    write_config: int = None

    @classmethod
    def from_int(cls, val):
        slot_cfg = cls()
        slot_cfg.read_key = val & 0xF
        slot_cfg.no_mac = bool(val & (1<<4))
        slot_cfg.limited_use = bool(val & (1<<5))
        slot_cfg.encrypt_read = bool(val & (1<<6))
        slot_cfg.is_secret = bool(val & (1<<7))
        slot_cfg.write_key = (val >> 8) & 0xF
        slot_cfg.write_config = val >> 12

        return slot_cfg

    def pack(self):
        val = 0
        val |= (self.read_key & 0xF) << 0
        val |= (self.no_mac & 0x1) << 4
        val |= (self.limited_use & 0x1) << 5
        val |= (self.encrypt_read & 0x1) << 6
        val |= (self.is_secret & 0x1) << 7
        val |= (self.write_key & 0xF) << 8
        val |= (self.write_config & 0xF) << 12
        return val

    def stringify(self):
        stringified = list()

        stringified.append(f"if public key:")
        if self.read_key == 0:
            stringified.append(f"\tused for source of checkmac/copy")
        else:
            stringified.append(f"\tread encryption key slot: {self.read_key:2d}")
        stringified.append(f"if private key:")
        if self.read_key & 0xC == 0x8:
            stringified.append(f"\tmaster secret in slot N+1")
        else:
            stringified.append(f"\tECDH master secret output in clear")
        stringified.append(f"\texternal signatures of messages " + ("are" if self.read_key & 0x1 else "are NOT") + " enabled")
        stringified.append(f"\tinternal signatures of messages " + ("are" if self.read_key & 0x2 else "are NOT") + " enabled")
        stringified.append(f"\tECDH operation " + ("is" if self.read_key & 0x4 else "is NOT") + " permitted")
        
        stringified.append(f"no_mac: {self.no_mac:b}")

        stringified.append(f"limited_use: {self.limited_use:b}")

        stringified.append(f"encrypt_read: {self.encrypt_read:b}")

        stringified.append(f"is_secret: {self.is_secret:b}")

        stringified.append(f"write_key validation/encryption slot: {self.write_key:2d}")
        
        stringified.append(f"write_config: {self.write_config:02X}")
        if self.write_config == 0:
            write = "always"
        elif self.write_config == 1:
            write = "pub_invalid"
        elif self.write_config & 0xE == 0x2:
            write = "never"
        elif self.write_config & 0xC == 0x8:
            write = "never"
        elif self.write_config & 0x4 == 0x4:
            write = "encrypt"
        else:
            raise ValueError(f"Bad write_config value {self.write_config:02X}")
        stringified.append(f"\twrite command:" + write)
        if self.write_config & 0xB == 0x2:
            derive_key = "target w/o MAC"
        elif self.write_config & 0xB == 0xA:
            derive_key = "target w/ MAC"
        elif self.write_config & 0xB == 0x3:
            derive_key = "parent w/ MAC"
        elif self.write_config & 0xB == 0xB:
            derive_key = "parent w/ MAC"
        elif self.write_config & 0x2 == 0x0:
            derive_key = "disabled"
        else:
            raise ValueError(f"Bad write_config value {self.write_config:02X}")
        stringified.append(f"\tderive_key command: " + derive_key)
        stringified.append(f"\tgenkey command: " + str(bool(self.write_config & 0x2)))
        stringified.append(f"\tprivwrite command: " + str(bool(self.write_config & 0x4)))

        return "\n".join(stringified)




@dataclass
class ATECC608_KeyConfig:
    private: bool = None
    pub_info: bool = None
    key_type: int = None
    lockable: bool = None
    req_random: bool = None
    req_auth: bool = None
    auth_key: int = None
    persistent_disable: bool = None
    rfu: bool = None
    x509_id: int = None
    

    @classmethod
    def from_int(cls, val):
        slot_cfg = cls()
        slot_cfg.private = bool(val & (1<<0))
        slot_cfg.pub_info = bool(val & (1<<1))
        slot_cfg.key_type = (val >> 2) & 0x7
        slot_cfg.lockable = bool(val & (1<<5))
        slot_cfg.req_random = bool(val & (1<<6))
        slot_cfg.req_auth = bool(val & (1<<7))
        slot_cfg.auth_key = (val >> 8) & 0xF
        slot_cfg.persistent_disable = bool(val & (1<<12))
        slot_cfg.rfu = bool(val & (1<<13))
        slot_cfg.x509_id = (val >> 14) & 0x3

        return slot_cfg

    def pack(self):
        val = 0
        val |= (self.private & 0x1) << 0
        val |= (self.pub_info & 0x1) << 1
        val |= (self.key_type & 0x7) << 2
        val |= (self.lockable & 0x1) << 5
        val |= (self.req_random & 0x1) << 6
        val |= (self.req_auth & 0x1) << 7
        val |= (self.auth_key & 0xF) << 7
        val |= (self.persistent_disable & 0x1) << 12
        val |= (self.rfu & 0x1) << 13
        val |= (self.x509_id & 0x3) << 14
        return val


    def stringify(self):
        stringified = list()

        stringified.append("key is " + "NOT " * (not self.private) + "a private key")
        if self.private:
            stringified.append("the public key can " + "NOT " * (not self.pub_info) + "be generated")
        else:
            if self.key_type == 4:
                if self.pub_info:
                    stringified.append("the public key in this slot must be verified before validation")
                else:
                    stringified.append("the public key can be used for validation without verification")
            else:
                if self.pub_info:
                    stringified.append("writes by KDF are allowed")
                else:
                    stringified.append("writes by KDF are NOT allowed")
        key_type_name = {
            0: "RFU 0",
            1: "RFU 1",
            2: "RFU 2",
            3: "RFU 3",
            4: "P256 NIST ECC",
            5: "RFU 5",
            6: "AES",
            7: "SHA or data",
        }[self.key_type]
        stringified.append("key type: " + key_type_name)
        stringified.append(f"lockable: {self.lockable}")
        stringified.append("a random nonce is " + "NOT " * (self.req_random) + "required")
        stringified.append(f"auth required: {self.req_auth}")
        if self.req_auth:
            stringified.append(f"\tkey slot for authorization: {self.auth_key:d}")
        else:
            if self.auth_key:
                stringified.append(f"\tINVALID AUTH_KEY NUMBER: {self.auth_key:d}")
        stringified.append(f"persistent_disable: {self.persistent_disable}")
        if self.rfu:
            stringified.append(f"\tINVALID RFU: {self.rfu:b}")
        stringified.append(f"x509 format index: {self.x509_id}")

        return "\n".join(stringified)


@dataclass
class ATECC608_SecureBoot:
    mode: int = None
    persist: bool = None
    rand_nonce: bool = None
    signature_digest_slot: int = None
    pubkey_slot: int = None

    @classmethod
    def from_int(cls, val, verify=True):
        slot_cfg = cls()
        slot_cfg.mode = val & 0x3
        if verify:
            assert not bool(val & (1<<2))
        slot_cfg.persist = bool(val & (1<<3))
        slot_cfg.rand_nonce = bool(val & (1<<3))
        if verify:
            assert not (val >> 5) & 0x7
        slot_cfg.signature_digest_slot = (val >> 8) & 0xF
        slot_cfg.pubkey_slot = (val >> 12) & 0xF

        return slot_cfg

    def pack(self):
        val = 0
        val |= (self.mode & 0x3) << 0
        val |= (self.persist & 0x1) << 3
        val |= (self.rand_nonce & 0x1) << 4
        val |= (self.signature_digest_slot & 0xF) << 8
        val |= (self.pubkey_slot & 0xF) << 12
        return val


    def stringify(self):
        stringified = list()
        if self.mode == 0:
            stringified.append("secure boot: disabled")
        elif self.mode == 1:
            stringified.append("secure boot: FullBoth")
        elif self.mode == 2:
            stringified.append("secure boot: FullSig")
        elif self.mode == 3:
            stringified.append("secure boot: FullDig")

        stringified.append("persistent " + ("enabled" if self.persist else "disabled"))
        stringified.append("secure rand nonce " + ("enabled" if self.rand_nonce else "disabled"))

        stringified.append(f"signature_digest_slot: {self.signature_digest_slot:d}")
        stringified.append(f"pubkey_slot: {self.pubkey_slot:d}")
        
        return "\n".join(stringified)


@dataclass
class ATECC608_Config:
    serial: bytes = None
    revision: int = None
    aes_enable: int = None
    i2c_enable: bool = None
    reserved_15: int = None
    i2c_address: int = None
    reserved_17: int = None
    count_match: int = None
    chip_mode: int = None
    slot_config: list = None
    counter_0: int = None
    counter_1: int = None
    use_lock: int = None
    volatile_key_permission: int = None
    secure_boot: int = None
    kdflv_loc: int = None
    kdflv_str: int = None
    reserved_75: bytes = None
    user_extra: int = None
    user_extra_add: int = None
    lock_value: int = None
    lock_config: int = None
    slot_locked: int = None
    chip_options: int = None
    x509_format: list = None
    key_config: list = None

    NUM_SLOTS: typing.ClassVar[int] = 16

    def stringify(self):
        stringified = []
        stringified.append(f"serial: {self.serial.hex()}")
        stringified.append(f"revision: {self.revision:08X}")
        stringified.append(f"aes_enable: {bool(self.aes_enable)} ({self.aes_enable:02X})")
        stringified.append(f"i2c_enable: {bool(self.i2c_enable)} ({self.i2c_enable:02X})")
        stringified.append(f"reserved_15: {self.reserved_15:02X}")
        stringified.append(f"i2c_address: {self.i2c_address:02X}")
        stringified.append(f"reserved_17: {self.reserved_17:02X}")
        stringified.append("count_match:")
        if self.count_match & 1:
            stringified.append(f"\tenabled in slot {self.count_match>>4:2d}")
        else:
            stringified.append("\tdisabled")
        if self.count_match & 0xE:
            stringified.append(f"INVALID COUNT_MATCH 0x{self.count_match:02X}")
        stringified.append("chip_mode:")
        if self.chip_mode & 1:
            stringified.append(f"\ti2c address from user_extra_add (if non-zero): {self.user_extra_add:02X}")
        else:
            stringified.append(f"\ti2c address from i2c_address: {self.i2c_address:02X}")
        stringified.append("\tttl reference: " + ("VCC" if self.chip_mode & 0x2 else "fixed"))
        stringified.append("\twatchdog: " + ("10s" if self.chip_mode & 0x4 else "1.3s"))

        clock_divider = self.chip_mode >> 3
        if clock_divider not in (0b00000, 0b01101, 0b00101):
            stringified.append(f"\tBAD CLOCK DIVIDER: {clock_divider:01X}")
        else:
            stringified.append(f"\tclock divider: {clock_divider:01X}")

        stringified.append("slots:")
        for i in range(self.NUM_SLOTS):
            stringified.append(f"\t{i:2d}: " + ("LOCKED" if self.slot_locked & (1<<i) else "UNLOCKED"))
            slot_config_val = self.slot_config[i]
            key_config_val = self.key_config[i]
            stringified.append(f"\t\tslot_config: {slot_config_val:04X}")
            slot_cfg = ATECC608_SlotConfig.from_int(slot_config_val)
            stringified.append(textwrap.indent(slot_cfg.stringify(), "\t\t\t"))
            stringified.append(f"\t\tkey_config: {key_config_val:04X}")
            key_cfg = ATECC608_KeyConfig.from_int(key_config_val)
            stringified.append(textwrap.indent(key_cfg.stringify(), "\t\t\t"))

        stringified.append(f"counter_0: {self.counter_0:016X}")
        stringified.append(f"counter_1: {self.counter_1:016X}")
        
        stringified.append(f"use_lock enable: {self.use_lock & 0xF:X}")
        stringified.append(f"use_lock key: {self.use_lock >> 4:X}")

        if self.volatile_key_permission & 0x80:
            stringified.append(f"volatile_key_permission enabled in slot: {self.volatile_key_permission & 0xF:d}")
        else:
            stringified.append(f"volatile_key_permission disabled (in slot: {self.volatile_key_permission & 0xF:d})")
        if self.volatile_key_permission & 0x70:
            stringified.append(f"INVALID volatile_key_permission bits: {self.volatile_key_permission:02X}")

        stringified.append(f"secure_boot: {self.secure_boot:04X}")
        secure_boot = ATECC608_SecureBoot.from_int(self.secure_boot)
        stringified.append(textwrap.indent(secure_boot.stringify(), "\t"))

        stringified.append(f"kdf message must have bytes {self.kdflv_str.hex()} at position {self.kdflv_loc:d}")

        stringified.append(f"user_extra: {self.user_extra:02X}")
        stringified.append(f"user_extra_add: {self.user_extra_add:02X}")

        if self.lock_value == 0x00:
            stringified.append("data/otp: LOCKED")
        elif self.lock_value == 0x55:
            stringified.append("data/otp: UNLOCKED")
        else:
            stringified.append(f"INVALID DATA/OTP LOCK MODE 0x{self.lock_value:02X}")
        if self.lock_config == 0x00:
            stringified.append("config: LOCKED")
        elif self.lock_config == 0x55:
            stringified.append("config: UNLOCKED")
        else:
            stringified.append(f"INVALID CONFIG LOCK MODE 0x{self.lock_config:02X}")
        
        stringified.append(f"slot_locked: {self.slot_locked:016b}")

        stringified.append(f"chip_options: ({self.chip_options:04X})")
        stringified.append(f"\tpower on self test: " + ("enabled" if self.chip_options & 1 else "disabled"))
        stringified.append(f"\tio protection key enable: " + ("enabled" if ((self.chip_options >> 1) & 1) else "disabled"))
        stringified.append(f"\taes kdf enabled: " + ("enabled" if ((self.chip_options >> 2) & 1) else "disabled"))
        if ((self.chip_options >> 3) & 0x1F) == 1:
            # According to the preliminary datasheet, this isn't allowed,
            # but I have chips from Microchip configured like this.
            # I really want the full datasheet, but I don't think I want the NDA.
            stringified.append(f"\tWEIRD chip_options bits 3-7: {(self.chip_options >> 3) & 0x1F:02X}")
        elif (self.chip_options >> 3) & 0x1F:
            stringified.append(f"\tINVALID CHIP_OPTIONS BITS 3-7: {(self.chip_options >> 3) & 0x1F:02X}")
        
        ecdh_protection = (self.chip_options >> 8) & 0x3 # TODO
        kdf_protection = (self.chip_options >> 10) & 0x3 # TODO
        io_protection_key = (self.chip_options >> 12) & 0xF # TODO
        # TODO

        stringified.append(f"x509 format: {self.x509_format}")
        if all (f == 0 for f in self.x509_format):
            stringified.append("\tnot used")
        else:
            for i in range(4):
                val = self.x509_format[i]
                template_length = val >> 4
                if template_length:
                    block = val & 0xF
                    stringified.append(f"\tblock {block:02d} has x509 of length {template_length}")
        return "\n".join(stringified)


    @classmethod
    def from_config_block(cls, block):
        if len(block) != 128:
            raise ValueError("Incorrect block size %d != 128" % len(block))

        index = 0
        def r(fmt):
            nonlocal index
            if isinstance(fmt, str):
                size = struct.calcsize(fmt)
                val = struct.unpack("<" + fmt, block[index:index+size])[0]
                index += size
            elif isinstance(fmt, int):
                val = block[index:index+fmt]
                index += fmt
            return val

        cfg = cls()

        serial = r(4)
        cfg.revision = r("I")
        cfg.serial = serial + r(5)
        cfg.aes_enable = r("B")
        cfg.i2c_enable = r("?")
        cfg.reserved_15 = r("B")
        cfg.i2c_address = r("B")
        cfg.reserved_17 = r("B")
        cfg.count_match = r("B")
        cfg.chip_mode = r("B")
        cfg.slot_config = [r("H") for i in range(16)]
        cfg.counter_0 = r("Q")
        cfg.counter_1 = r("Q")
        cfg.use_lock = r("B")
        cfg.volatile_key_permission = r("B")
        cfg.secure_boot = r("H")
        cfg.kdflv_loc = r("B")
        cfg.kdflv_str = r(2)
        cfg.reserved_75 = r(9)
        cfg.user_extra = r("B")
        cfg.user_extra_add = r("B")
        cfg.lock_value = r("B")
        cfg.lock_config =  r("B")
        cfg.slot_locked = r("H")
        cfg.chip_options = r("H")
        cfg.x509_format = list(r(4))
        cfg.key_config = [r("H") for i in range(16)]
        # print("at", index)

        assert index == 128, "Didn't parse all config bytes. Programmer error."

        return cfg




# def brute_check():
#     for i in range(65536):
#         key_config = ATECC608_KeyConfig.from_int(i)
#         v = key_config.pack()
#         assert v == i, f"keycfg failed {v:016b} != {i:016b}"
#         slot_config = ATECC608_SlotConfig.from_int(i)
#         v = slot_config.pack()
#         assert v == i, f"sltcfg failed {v:016b} != {i:016b}"
#         secure_boot = ATECC608_SecureBoot.from_int(i, verify=False)
#         v = secure_boot.pack()
#         assert v == i, f"secubt failed {v:016b} != {i:016b}"
#     print("finished checking packing")






if __name__ == '__main__':
    cfg = ATECC608_Config.from_config_block(CONFIG_FACTORY_TNGTLS)
    print(cfg.stringify())
