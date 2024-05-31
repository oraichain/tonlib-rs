use std::io::Cursor;

use bitstream_io::{BigEndian, BitRead, BitReader};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::identities::Zero;
use num_traits::FromPrimitive;

use crate::address::TonAddress;
use crate::cell::util::*;
use crate::cell::{MapTonCellError, TonCellError};

use super::Cell;

pub struct CellParser<'a> {
    pub(crate) bit_len: usize,
    pub(crate) bit_reader: BitReader<Cursor<&'a Vec<u8>>, BigEndian>,
}

impl CellParser<'_> {
    pub fn remaining_bits(&mut self) -> usize {
        let pos = self.bit_reader.position_in_bits().unwrap_or_default() as usize;
        if self.bit_len > pos {
            self.bit_len - pos
        } else {
            0
        }
    }

    /// Return number of full bytes remaining
    pub fn remaining_bytes(&mut self) -> usize {
        self.remaining_bits() / 8
    }

    pub fn load_bit(&mut self) -> Result<bool, TonCellError> {
        self.bit_reader.read_bit().map_cell_parser_error()
    }

    pub fn load_u8(&mut self, bit_len: usize) -> Result<u8, TonCellError> {
        self.bit_reader
            .read::<u8>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_i8(&mut self, bit_len: usize) -> Result<i8, TonCellError> {
        self.bit_reader
            .read::<i8>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_u16(&mut self, bit_len: usize) -> Result<u16, TonCellError> {
        self.bit_reader
            .read::<u16>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_i16(&mut self, bit_len: usize) -> Result<i16, TonCellError> {
        self.bit_reader
            .read::<i16>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_u32(&mut self, bit_len: usize) -> Result<u32, TonCellError> {
        self.bit_reader
            .read::<u32>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_i32(&mut self, bit_len: usize) -> Result<i32, TonCellError> {
        self.bit_reader
            .read::<i32>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_u64(&mut self, bit_len: usize) -> Result<u64, TonCellError> {
        self.bit_reader
            .read::<u64>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_i64(&mut self, bit_len: usize) -> Result<i64, TonCellError> {
        self.bit_reader
            .read::<i64>(bit_len as u32)
            .map_cell_parser_error()
    }

    pub fn load_uint(&mut self, bit_len: usize) -> Result<BigUint, TonCellError> {
        let num_words = (bit_len + 31) / 32;
        let high_word_bits = if bit_len % 32 == 0 { 32 } else { bit_len % 32 };
        let mut words: Vec<u32> = vec![0_u32; num_words];
        let high_word = self.load_u32(high_word_bits)?;
        words[num_words - 1] = high_word;
        for i in (0..num_words - 1).rev() {
            let word = self.load_u32(32)?;
            words[i] = word;
        }
        let big_uint = BigUint::new(words);
        Ok(big_uint)
    }

    pub fn load_int(&mut self, bit_len: usize) -> Result<BigInt, TonCellError> {
        let num_words = (bit_len + 31) / 32;
        let high_word_bits = if bit_len % 32 == 0 { 32 } else { bit_len % 32 };
        let mut words: Vec<u32> = vec![0_u32; num_words];
        let high_word = self.load_u32(high_word_bits)?;
        let sign = if (high_word & (1 << 31)) == 0 {
            Sign::Plus
        } else {
            Sign::Minus
        };
        words[num_words - 1] = high_word;
        for i in (0..num_words - 1).rev() {
            let word = self.load_u32(32)?;
            words[i] = word;
        }
        let big_uint = BigInt::new(sign, words);
        Ok(big_uint)
    }

    pub fn load_uint_less(&mut self, bit_len: usize) -> Result<BigUint, TonCellError> {
        self.load_uint_le(bit_len - 1)
    }

    pub fn load_uint_le(&mut self, bit_len: usize) -> Result<BigUint, TonCellError> {
        let mut last_one = -1i64;
        let mut l = 1;
        for i in 0..32 {
            if (bit_len & l) > 0 {
                last_one = i;
            }
            l = l << 1;
        }
        if last_one == -1 {
            return Err(TonCellError::cell_parser_error("not a UintLe"));
        }
        last_one += 1;
        self.load_uint(last_one as usize)
    }

    pub fn load_byte(&mut self) -> Result<u8, TonCellError> {
        self.load_u8(8)
    }

    pub fn load_slice(&mut self, slice: &mut [u8]) -> Result<(), TonCellError> {
        self.bit_reader.read_bytes(slice).map_cell_parser_error()
    }

    pub fn load_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, TonCellError> {
        let mut res = vec![0_u8; num_bytes];
        self.load_slice(res.as_mut_slice())?;
        Ok(res)
    }

    pub fn load_bits_to_slice(
        &mut self,
        num_bits: usize,
        slice: &mut [u8],
    ) -> Result<(), TonCellError> {
        self.bit_reader.read_bits(num_bits, slice)?;
        Ok(())
    }

    pub fn load_bits(&mut self, num_bits: usize) -> Result<Vec<u8>, TonCellError> {
        let total_bytes = (num_bits + 7) / 8;
        let mut res = vec![0_u8; total_bytes];
        self.load_bits_to_slice(num_bits, res.as_mut_slice())?;
        Ok(res)
    }

    pub fn load_utf8(&mut self, num_bytes: usize) -> Result<String, TonCellError> {
        let bytes = self.load_bytes(num_bytes)?;
        String::from_utf8(bytes).map_cell_parser_error()
    }

    pub fn load_utf8_lossy(&mut self, num_bytes: usize) -> Result<String, TonCellError> {
        let bytes = self.load_bytes(num_bytes)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub fn load_coins(&mut self) -> Result<BigUint, TonCellError> {
        let num_bytes = self.load_u8(4)?;
        if num_bytes == 0 {
            Ok(BigUint::zero())
        } else {
            self.load_uint((num_bytes * 8) as usize)
        }
    }

    pub fn load_address(&mut self) -> Result<TonAddress, TonCellError> {
        let tp = self.bit_reader.read::<u8>(2).map_cell_parser_error()?;
        match tp {
            0 => Ok(TonAddress::null()),
            2 => {
                let _res1 = self.bit_reader.read::<u8>(1).map_cell_parser_error()?;
                let wc = self.bit_reader.read::<u8>(8).map_cell_parser_error()?;
                let mut hash_part = [0_u8; 32];
                self.bit_reader
                    .read_bytes(&mut hash_part)
                    .map_cell_parser_error()?;
                let addr = TonAddress::new(wc as i32, &hash_part);
                Ok(addr)
            }
            _ => Err(TonCellError::InvalidAddressType(tp)),
        }
    }

    pub fn load_unary_length(&mut self) -> Result<usize, TonCellError> {
        let mut res = 0;
        while self.load_bit()? {
            res += 1;
        }
        Ok(res)
    }

    pub fn ensure_empty(&mut self) -> Result<(), TonCellError> {
        let remaining_bits = self.remaining_bits();
        if remaining_bits == 0 {
            Ok(())
        } else {
            Err(TonCellError::NonEmptyReader(remaining_bits))
        }
    }

    pub fn skip_bits(&mut self, num_bits: usize) -> Result<(), TonCellError> {
        self.bit_reader
            .skip(num_bits as u32)
            .map_cell_parser_error()
    }

    pub fn load_shard_ident(&mut self) -> Result<(), TonCellError> {
        let ident = self.load_uint(2)?;
        if !ident.is_zero() {
            return Err(TonCellError::cell_parser_error("not a ShardIdent"));
        }
        let shard_pfx_bits = self.load_uint_le(60)?;
        let workchain_id = self.load_i32(32)?;
        let shard_prefix = self.load_u64(64)?;

        // FIXME: return shard ident struct
        Ok(())
    }

    pub fn load_global_version(&mut self) -> Result<(), TonCellError> {
        let code = self.load_u8(8)?;
        if code != 0xc4 {
            return Err(TonCellError::cell_parser_error("not a GlobalVersion"));
        }
        let version = self.load_u32(32)?;
        let capabilities = self.load_u64(64)?;
        println!(
            "version and capabilities: {:?}, {:?}",
            version, capabilities
        );
        Ok(())
    }

    pub fn load_label(&mut self, m: usize) -> Result<(BigUint, usize), TonCellError> {
        let _type = self.load_bit()?;
        if !_type {
            let n = self.load_unary_length()?;
            if n > 0 {
                let s = self.load_uint(n)?;
                return Ok((s, n));
            }
            return Ok((BigUint::from_u8(0).unwrap(), n));
        }
        let type2 = self.load_bit()?;
        if !type2 {
            let n = self.load_uint_le(m)?;
            let n_usize = usize::try_from(n.clone()).map_err(TonCellError::cell_parser_error)?;
            let s = self.load_uint(n_usize)?;
            return Ok((s, n_usize));
        }
        let v = self.load_bit()?;
        let v_value = if v { 1 } else { 0 };
        let n = self.load_uint_le(m)?;
        let n_usize = usize::try_from(n.clone()).map_err(TonCellError::cell_parser_error)?;
        let mut s = BigUint::from_u64(0).unwrap();
        for _ in 0..n_usize {
            s = s << 1;
            s = s | BigUint::from_usize(v_value).unwrap();
        }
        Ok((s, n_usize))
    }

    pub fn load_var_uinteger(
        &mut self,
        bit_len: usize,
    ) -> Result<(BigUint, BigUint), TonCellError> {
        let len = self.load_uint_less(bit_len)?;
        let len_usize = usize::try_from(len.clone()).map_err(TonCellError::cell_parser_error)?;
        let mut value = BigUint::zero();
        if len_usize == 0 {
            // TODO
        } else {
            value = self.load_uint(len_usize * 8)?;
        }
        Ok((len, value))
    }

    pub fn load_sig_pub_key(&mut self) -> Result<Vec<u8>, TonCellError> {
        let magic = self.load_u32(32)?;
        if magic != 0x8e81278a {
            return Err(TonCellError::cell_parser_error("Not a SigPubKey"));
        }
        let pubKey = self.load_bits(256)?;
        println!("pub key: {:?}", hex::encode(pubKey.clone()));
        Ok(pubKey)
    }
}
